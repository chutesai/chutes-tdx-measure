#!/usr/bin/env bash
# Copyright (c) 2026 Chutes Global Corp
# SPDX-License-Identifier: Apache-2.0
#
# Fetch Chutes' TDVF (OVMF.inteltdx.fd) into tests/fixtures/ for tests/chutes.rs, from the public
# chutesai/sek8s repository at a fixed commit, and check its sha256.
#
# Idempotent: skips the download if the file is already present with the expected sha256.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/fixtures/OVMF.inteltdx.fd"
url=https://raw.githubusercontent.com/chutesai/sek8s/d98f3fbf44669b918a1bbce7422c5187fc8102b1/firmware/OVMF.inteltdx.fd
expected_sha256=01731a86fa3665caccaa4a1906cdd9276b0a53fc5921dbcc70970219ac942169

if [[ -f "$out" ]] \
   && [[ "$(sha256sum "$out" | awk '{print $1}')" == "$expected_sha256" ]]; then
    echo "$out already present and matches expected sha256"
    exit 0
fi

mkdir -p "$here/fixtures"
tmp="$(mktemp "$here/fixtures/.OVMF.inteltdx.fd.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

curl -fsSL --retry 3 -o "$tmp" "$url"
actual="$(sha256sum "$tmp" | awk '{print $1}')"
if [[ "$actual" != "$expected_sha256" ]]; then
    echo "OVMF.inteltdx.fd sha256 mismatch: got $actual, expected $expected_sha256" >&2
    exit 1
fi
chmod 0644 "$tmp"
mv "$tmp" "$out"
trap - EXIT
echo "$out ready (sha256=$expected_sha256)"
