#!/usr/bin/env bash
# Compile and run the Java wrapper test suite without Maven/Gradle.
#
# Requirements:
#   - JDK 21+ (on JDK 21 the java.lang.foreign FFM API is a preview feature,
#     hence --enable-preview at both compile and run time; final on JDK 22+).
#   - The native core built at ../../build/libhymmalm.so, or HYMMALM_LIB set
#     to the full path of the shared library.
#
# HLM_TIMESYNC=off is REQUIRED for the flow tests: it makes the native client
# take its trusted evaluation time from the mock server's GET /api/DateTime
# (2026-07-10T00:00:00Z) instead of syncing real time, so the expected license
# statuses are deterministic. Java cannot setenv() for its own process, so
# this script must export it before launching the JVM.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${HYMMALM_LIB:-$DIR/../../build/libhymmalm.so}"
OUT="$DIR/out"

if [[ ! -e "$LIB" ]]; then
    echo "error: native library not found at $LIB" >&2
    echo "build it (cmake) or set HYMMALM_LIB to the full path of libhymmalm.so" >&2
    exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== compiling (JDK 21 preview: java.lang.foreign) =="
# shellcheck disable=SC2046
javac --release 21 --enable-preview -d "$OUT" \
    $(find "$DIR/src/main/java" "$DIR/src/test/java" -name '*.java')

echo "== running tests =="
cd "$DIR"  # tests resolve ../../tests/vectors relative to this directory
HLM_TIMESYNC=off HYMMALM_LIB="$LIB" \
    java --enable-preview --enable-native-access=ALL-UNNAMED \
    -cp "$OUT" com.hymma.licensing.TestRunner
