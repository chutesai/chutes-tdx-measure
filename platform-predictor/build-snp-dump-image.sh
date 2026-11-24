#!/usr/bin/env bash
# Reproducible build of the SEV-SNP platform-table dump image (Dockerfile.qemu-acpi-dump-snp).
#
#   ./build-snp-dump-image.sh [--load] OUT_DIR
#
# Fetches the three QEMU source package files that Dockerfile.qemu-acpi-dump-snp.args names from
# snapshot.ubuntu.com (each checked against its sha256 there), copies them and pci-bar-stub.c into
# the build context with fixed modes and SOURCE_DATE_EPOCH as their time, and builds with BuildKit
# pinned by digest, daemonless in a privileged container, no cache, into an OCI archive with
# rewrite-timestamp. Two builders get the same manifest digest. Writes OUT_DIR/image.tar and
# OUT_DIR/digest and prints the digest. With --load, the archive is loaded into Docker as
# chutes-tdx-measure/qemu-acpi-dump-snp, the name tdx-measure --snp-dump-image takes with the digest
# (Docker's containerd image store keeps the manifest digest of a loaded image).
set -euo pipefail

BUILDKIT_IMAGE=moby/buildkit@sha256:de10faf919fc71ba4eb1dd7bd6449566d012b0c9436b1c61bfee21d621b009aa
NAME=chutes-tdx-measure/qemu-acpi-dump-snp
SOURCE_URL=http://snapshot.ubuntu.com/ubuntu/20260901T000000Z/pool/main/q/qemu
here=$(cd "$(dirname "$0")" && pwd)
load=0
if [ "${1:-}" = --load ]; then
  load=1
  shift
fi
[ $# -eq 1 ] || { echo "usage: build-snp-dump-image.sh [--load] OUT_DIR" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)
args=$here/Dockerfile.qemu-acpi-dump-snp.args
arg() { sed -n "s/^$1=//p" "$args"; }

work=$(mktemp -d "${TMPDIR:-/var/tmp}/snp-dump-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/context"
for kind in DSC ORIG DEBIAN; do
  file=$(arg "QEMU_$kind")
  sha=$(arg "QEMU_${kind}_SHA256")
  curl -fsSL --retry 5 -o "$work/context/$file" "$SOURCE_URL/$file"
  [ "$(sha256sum < "$work/context/$file" | cut -c1-64)" = "$sha" ] || { echo "sha256 mismatch: $file" >&2; exit 1; }
done
cp "$here/pci-bar-stub.c" "$work/context/pci-bar-stub.c"
chmod 0644 "$work/context"/*
touch -d "@$(arg SOURCE_DATE_EPOCH)" "$work/context" "$work/context"/*

build_args=()
while IFS= read -r line; do
  case $line in '' | '#'*) continue ;; esac
  build_args+=(--opt "build-arg:$line")
done < "$args"

rm -f "$out/image.tar" "$out/digest"
docker run --rm --privileged \
  -v "$work/context:/ctx:ro" -v "$here:/dockerfile:ro" -v "$out:/out" \
  --entrypoint buildctl-daemonless.sh "$BUILDKIT_IMAGE" \
  build --frontend dockerfile.v0 \
  --local context=/ctx --local dockerfile=/dockerfile \
  --opt filename=Dockerfile.qemu-acpi-dump-snp \
  --opt platform=linux/amd64 \
  "${build_args[@]}" \
  --no-cache \
  --output "type=oci,dest=/out/image.tar,rewrite-timestamp=true,oci-mediatypes=true,name=$NAME"

digest=$(tar -xOf "$out/image.tar" index.json |
  python3 -I -c 'import json, sys; m = json.load(sys.stdin)["manifests"]; assert len(m) == 1, m; print(m[0]["digest"])')
echo "$digest" > "$out/digest"
echo "$NAME@$digest"
if [ "$load" = 1 ]; then
  docker load -i "$out/image.tar" > /dev/null
  docker image inspect --format '{{.Id}}' "$NAME@$digest" > /dev/null
fi
