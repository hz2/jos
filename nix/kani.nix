{ lib
, stdenv
, fetchurl
, autoPatchelfHook
, makeWrapper
, zlib
, openssl
}:

# Kani ships a prebuilt release tarball containing the `kani` / `cargo-kani` drivers plus a
# bundled CBMC and friends. These are dynamically linked binaries that need patching onto the
# Nix runtime. On first `cargo kani` run, Kani also fetches/builds a matching toolchain via
# `cargo kani setup`; we keep that behavior (it caches under ~/.kani) rather than trying to
# fully hermeticize it here — the goal is a working `verify` shell, not a sandboxed package.

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

  # kani-compiler links against librustc_driver from kani's own bundled rust
  # toolchain, which lives elsewhere in the release tree and is resolved at
  # runtime, not by autoPatchelf. tell autoPatchelf not to fail on it.
  autoPatchelfIgnoreMissingDeps = [
    "librustc_driver-*.so"
    "libstd-*.so"
  ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/kani $out/bin
    cp -r ./* $out/libexec/kani/

    # the kani release puts its driver binaries under bin/ inside the tree.
    # wrap whichever of kani / cargo-kani exist there onto $out/bin.
    for b in kani cargo-kani; do
      if [ -e "$out/libexec/kani/bin/$b" ]; then
        chmod +x "$out/libexec/kani/bin/$b"
        makeWrapper "$out/libexec/kani/bin/$b" "$out/bin/$b"
      fi
    done

    runHook postInstall
  '';

  dontStrip = true;

  meta = with lib; {
    description = "Kani — a bit-precise bounded model checker for Rust (prebuilt release, patched for NixOS)";
    homepage = "https://github.com/model-checking/kani";
    license = with licenses; [ asl20 mit ];
    platforms = [ "x86_64-linux" ];
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
  };
}
