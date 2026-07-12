//! Compiles the vendored C core (license-management-core) and links it
//! statically. The sources live under `csrc/` inside the crate (copied from
//! the repository's `src/` + `include/` by sync-csrc.sh) so the published
//! crates.io tarball is self-contained.

use std::env;
use std::path::PathBuf;

/// Sources compiled on every platform.
const COMMON_SOURCES: &[&str] = &[
    "src/core/hlm_sha256.c",
    "src/core/hlm_sha512.c",
    "src/core/hlm_b64url.c",
    "src/core/hlm_json.c",
    "src/core/hlm_bignum.c",
    "src/core/hlm_jws.c",
    "src/core/hlm_license.c",
    "src/core/hlm_client.c",
    "src/core/hlm_ffi.c",
    "src/crypto/hlm_rsa.c",
    "src/crypto/hlm_p256.c",
    "src/crypto/hlm_ed25519.c",
    "src/crypto/hlm_crypto_portable.c",
    "src/ports/hlm_ports_common.c",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir.join("csrc");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut build = cc::Build::new();
    build
        .include(root.join("include"))
        .include(root.join("src/core"))
        .include(root.join("src/crypto"))
        // C99, matching the CMake build (CMAKE_C_STANDARD 99 without
        // C_EXTENSIONS OFF => gnu99 on gcc/clang; strict -std=c99 would set
        // __STRICT_ANSI__ and hide the POSIX declarations the ports need).
        .std(if target_os == "windows" { "c99" } else { "gnu99" });

    for src in COMMON_SOURCES {
        build.file(root.join(src));
    }

    if target_os == "windows" {
        build.file(root.join("src/crypto/hlm_crypto_cng.c"));
        build.file(root.join("src/ports/hlm_port_win.c"));
    } else {
        build.file(root.join("src/ports/hlm_port_posix.c"));
    }

    build.compile("hymmalm");

    if target_os == "windows" {
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=advapi32");
    } else if target_os == "linux" {
        // The POSIX port dlopen()s libcurl at runtime.
        println!("cargo:rustc-link-lib=dl");
    }

    println!("cargo:rerun-if-changed={}", root.join("src").display());
    println!("cargo:rerun-if-changed={}", root.join("include").display());
}
