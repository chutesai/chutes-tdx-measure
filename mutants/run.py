#!/usr/bin/env python3
"""Mutation check: every mutant in mutants/mutants.json must make its test command fail.

    python3 mutants/run.py [--python PATH] [--only ID ...] [--out results.json]

Each mutant is ``{"id", "check", "edits": [{"file", "old", "new"}], "test": [argv...]}``: one check of
the code removed or weakened. The repository (without .git and build output) is copied to a scratch
directory per mutant, every ``old`` must occur exactly once and is replaced by ``new``, and the test
command runs there. A mutant is killed when the command exits non-zero because a test failed; a
mutant that does not compile or times out is invalid (it proves nothing) and fails the run. The
unmutated copy must pass every distinct test command first, else the run is void. ``{python}`` in a command is
``--python``. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Output that means the mutant did not build or load: not a kill.
INVALID = ("[build failed]", "[setup failed]", "SyntaxError", "IndentationError", "ImportError while", "error: could not compile")
IGNORE = shutil.ignore_patterns(".git", "out", "__pycache__", "*.pyc", ".pytest_cache", "mkosi.output", "mkosi.cache")


def command(argv, python):
    return [python if part == "{python}" else part for part in argv]


def run(argv, cwd, timeout):
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        code, out = proc.returncode, (proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired as exc:
        code, out = 124, f"timeout after {timeout}s: {exc}"
    return code, out, time.monotonic() - started


def failing_line(out: str) -> str:
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    for line in lines:
        if line.startswith(("--- FAIL", "FAILED ", "FAIL\t", "panic:")) or "Error" in line[:40]:
            return line[:200]
    return lines[-1][:200] if lines else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--out")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    with open(os.path.join(HERE, "mutants.json")) as stream:
        mutants = json.load(stream)["mutants"]
    if args.only:
        mutants = [m for m in mutants if m["id"] in args.only]
    scratch = tempfile.mkdtemp(prefix="mutants-")
    base = os.path.join(scratch, "base")
    shutil.copytree(ROOT, base, ignore=IGNORE)
    for argv in sorted({tuple(m["test"]) for m in mutants}):
        code, out, _ = run(command(argv, args.python), base, args.timeout)
        if code != 0:
            print("BASELINE FAILS:", " ".join(argv), "\n", out[-3000:])
            sys.exit(2)
        print("baseline passes:", " ".join(argv))
    results = []
    for m in mutants:
        work = os.path.join(scratch, m["id"])
        shutil.copytree(base, work)
        for edit in m["edits"]:
            path = os.path.join(work, edit["file"])
            with open(path, encoding="utf-8") as stream:
                text = stream.read()
            if text.count(edit["old"]) != 1:
                print(f"{m['id']}: the edit's old text occurs {text.count(edit['old'])} times in {edit['file']}")
                sys.exit(2)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(text.replace(edit["old"], edit["new"]))
        code, out, seconds = run(command(m["test"], args.python), work, args.timeout)
        invalid = code == 124 or any(marker in out for marker in INVALID)
        killed = code != 0 and not invalid
        results.append({"id": m["id"], "check": m["check"], "killed": killed, "invalid": invalid, "exit": code,
                        "seconds": round(seconds, 1), "by": failing_line(out) if code else ""})
        state = "INVALID " if invalid else ("killed  " if killed else "SURVIVED")
        print(f"{state} {m['id']:6} {m['check']}" + (f"  [{failing_line(out)}]" if code else ""))
        shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(scratch, ignore_errors=True)
    survived = [r for r in results if not r["killed"]]
    print(f"{len(results) - len(survived)}/{len(results)} mutants killed")
    if args.out:
        with open(args.out, "w") as stream:
            json.dump(results, stream, indent=1)
    sys.exit(1 if survived else 0)


if __name__ == "__main__":
    main()
