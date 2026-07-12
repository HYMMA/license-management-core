#!/usr/bin/env sh
# Vendor the C core into the crate under csrc/.
#
# `cargo publish` only packages files under the crate root, so build.rs
# cannot reach ../../src from the crates.io tarball — the sources must live
# here. The canonical sources are ../../src and ../../include; NEVER edit
# the copies. CI re-runs this script and fails if the copies drift.
set -eu
cd "$(dirname "$0")"

rm -rf csrc
mkdir -p csrc/src/core csrc/src/crypto csrc/src/ports csrc/include/hymma

cp ../../src/core/*.c ../../src/core/*.h csrc/src/core/
cp ../../src/crypto/*.c ../../src/crypto/*.h csrc/src/crypto/
cp ../../src/ports/*.c csrc/src/ports/
cp ../../include/hymma/*.h csrc/include/hymma/

echo "vendored $(find csrc -name '*.c' | wc -l | tr -d ' ') C files (canonical: ../../src, ../../include)"
