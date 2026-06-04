{ lib
, stdenv
, fetchurl
, autoPatchelfHook
, makeWrapper
, zlib
, openssl
, kaniToolchain
}:

# Kani ships a prebuilt release tarball containing the kani-driver / kani-compiler
# binaries plus a bundled CBMC. Two NixOS-specific problems to solve:
#
#  1. The user-facing `kani` and `cargo-kani` commands are not separate binaries;
#     `kani-driver` dispatches on argv[0]. So we provide them as SYMLINKS to
#     kani-driver (makeWrapper would change argv[0] and break the dispatch).
#
#  2. kani-driver execs `<kani>/libexec/kani/toolchain/bin/cargo` (a relative
#     `toolchain/` dir it expects `cargo kani setup` to have created as a
#     symlink to the matching rustup toolchain). And kani-compiler is a rustc
#     driver linked against librustc_driver-<hash>.so from that same toolchain
#     (nightly-2025-11-21, rustc 1.93). We satisfy both by symlinking
#     `toolchain` -> kaniToolchain (a full fenix nightly-2025-11-21 with
#     cargo+rustc+rust-src+rustc-dev+std) and putting its lib dir on
#     LD_LIBRARY_PATH so librustc_driver resolves.

stdenv.mkDerivation rec {
  pname = "kani";
  version = "0.67.0";

  src = fetchurl {
    url = "https://github.com/model-checking/kani/releases/download/kani-${version}/kani-${version}-x86_64-unknown-linux-gnu.tar.gz";
    hash = "sha256-O196/TtRYD7nINt7wbxP5GtaT1022q2ZOcS0xli1GsA=";
  };

  nativeBuildInputs = [ autoPatchelfHook makeWrapper ];
  buildInputs = [
    zlib
    openssl
    stdenv.cc.cc.lib
  ];

  # librustc_driver / libstd come from kaniRustcDev at runtime via LD_LIBRARY_PATH,
  # not from autoPatchelf. don't fail the build on them.
  autoPatchelfIgnoreMissingDeps = [
    "librustc_driver-*.so"
    "libstd-*.so"
  ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/kani $out/bin
    cp -r ./* $out/libexec/kani/

    # kani-driver execs ./toolchain/bin/cargo (and rustc, via RUSTC). point that
    # at the full matching fenix toolchain so cargo metadata / build-std work.
    ln -s "${kaniToolchain}" "$out/libexec/kani/toolchain"

    # kani-driver dispatches on argv[0]; expose `kani` and `cargo-kani` as
    # wrappers that preserve argv0, put the toolchain's librustc_driver on the
    # loader path for kani-compiler, and put kani's bin dir (cbmc, goto-cc,
    # goto-instrument, kani-compiler) on PATH so the driver can invoke them.
    for name in kani cargo-kani; do
      makeWrapper "$out/libexec/kani/bin/kani-driver" "$out/bin/$name" \
        --argv0 "$name" \
        --prefix LD_LIBRARY_PATH : "${kaniToolchain}/lib" \
        --prefix PATH : "$out/libexec/kani/bin"
    done

    runHook postInstall
  '';

  dontStrip = true;

  meta = with lib; {
    description = "Kani: a bit-precise bounded model checker for Rust (prebuilt release, patched for NixOS)";
    homepage = "https://github.com/model-checking/kani";
    license = with licenses; [ asl20 mit ];
    platforms = [ "x86_64-linux" ];
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
  };
}
