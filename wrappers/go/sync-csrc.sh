#!/usr/bin/env sh
# Vendor the C core into the Go module.
#
# A Go module zip contains only the wrappers/go subtree, so `go get`
# consumers never see ../../src — the sources must live here. cgo compiles
# every .c file in the package directory, which is why the copies are flat.
# The canonical sources are ../../src and ../../include; NEVER edit the
# copies. CI re-runs this script and fails if the copies drift.
set -eu
cd "$(dirname "$0")"

rm -f hlm_*.c hlm_*.h
rm -rf include

cp ../../src/core/*.c ../../src/core/*.h .
cp ../../src/crypto/*.c ../../src/crypto/*.h .
cp ../../src/ports/*.c .
mkdir -p include/hymma
cp ../../include/hymma/*.h include/hymma/

echo "vendored $(ls hlm_*.c | wc -l | tr -d ' ') C files (canonical: ../../src, ../../include)"
