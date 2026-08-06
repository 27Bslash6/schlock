#!/usr/bin/env bash
# Reproducible cross-compile of schlock-parse for the 5 supported targets
# (spec §7) plus MANIFEST.json generation.
#
# Determinism contract: CGO_ENABLED=0, -trimpath, -buildvcs=false, -s -w.
# Building twice from the same source + Go toolchain must yield
# byte-identical binaries — T9's CI rebuild-byte-equality job asserts this
# against the committed binaries, so any flag change here must be mirrored
# in MANIFEST.json's "build" field.
set -euo pipefail

cd "$(dirname "$0")"
BIN_DIR="${1:-$(git rev-parse --show-toplevel)/.claude-plugin/bin}"

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

for target in $TARGETS; do
    goos=${target%/*}
    goarch=${target#*/}
    ext=""
    [ "$goos" = "windows" ] && ext=".exe"
    out="$BIN_DIR/$goos-$goarch/schlock-parse$ext"
    mkdir -p "$(dirname "$out")"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-trimpath \
        go build -buildvcs=false -ldflags="-s -w" -o "$out" .
    echo "built $out"
done

MVDAN_VERSION=$(go list -m -f '{{.Version}}' mvdan.cc/sh/v3)
GO_VERSION=$(go env GOVERSION)

python3 - "$BIN_DIR" "$MVDAN_VERSION" "$GO_VERSION" <<'PYEOF'
import hashlib
import json
import pathlib
import sys

bin_dir, mvdan_version, go_version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
binaries = {
    str(p.relative_to(bin_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in sorted(bin_dir.glob("*/schlock-parse*"))
}
manifest = {
    "schema": 1,
    "mvdan_sh": mvdan_version,
    "go": go_version,
    "build": 'CGO_ENABLED=0 GOFLAGS=-trimpath go build -buildvcs=false -ldflags="-s -w"',
    "binaries": binaries,
}
(bin_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"wrote {bin_dir / 'MANIFEST.json'} ({len(binaries)} binaries)")
PYEOF
