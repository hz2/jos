{ lib
, stdenv
, fetchzip
, autoPatchelfHook
, makeWrapper
, zlib
, gcc-unwrapped
}:

# Verus ships a prebuilt release bundle: the `verus` driver, `rust_verify`, the verified
# `vstd` library, and a bundled `z3`. The binaries are dynamically linked against a normal
# loader/glibc/libstdc++ that don't exist at the expected paths on NixOS, so we autoPatchelf
# them onto the Nix runtime and expose `verus` on PATH.
#
# NOTE: Verus internally invokes its own pinned Rust toolchain (channel 1.95.0). The release
# bundle is built against that toolchain; we do not substitute the kernel's nightly here. The
# `verify` dev shell is where this lives, separate from the kernel build.

stdenv.mkDerivation rec {
  pname = "verus";
  version = "0.2026.05.31.5dd6d83";

  src = fetchzip {
    url = "https://github.com/verus-lang/verus/releases/download/release/${version}/verus-${version}-x86-linux.zip";
    hash = "sha256-WPwpWj9kZt6IueMVDNUsK6F8D77WTi22WhiJAKxv7iE=";
    stripRoot = false;
  };

  nativeBuildInputs = [ autoPatchelfHook makeWrapper ];
  buildInputs = [
    zlib
    gcc-unwrapped.lib # libstdc++
    stdenv.cc.cc.lib
  ];

  # rust_verify links against librustc_driver/libstd from verus's own bundled
  # rust toolchain, which sits alongside it in the release tree and is found at
  # runtime via rpath, not by autoPatchelf. don't fail the build on these.
  autoPatchelfIgnoreMissingDeps = [
    "librustc_driver-*.so"
    "libstd-*.so"
  ];

  # The archive layout is verus-x86-linux/{verus, rust_verify, z3, vstd.vir, ...}.
  # Keep the whole tree together (rust_verify resolves siblings relatively) and symlink
  # the user-facing `verus` entrypoint onto PATH.
  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/verus $out/bin
    cp -r ./* $out/libexec/verus/ 2>/dev/null || true
    # Some archives nest one level; handle both flat and nested layouts.
    if [ -d "$out/libexec/verus/verus-x86-linux" ]; then
      mv $out/libexec/verus/verus-x86-linux/* $out/libexec/verus/
      rmdir $out/libexec/verus/verus-x86-linux || true
    fi

    chmod +x $out/libexec/verus/verus $out/libexec/verus/rust_verify $out/libexec/verus/z3 2>/dev/null || true

    makeWrapper $out/libexec/verus/verus $out/bin/verus

    runHook postInstall
  '';

  # Z3 and the rust_verify binary need exec perms preserved; autoPatchelf handles linking.
  dontStrip = true;

  meta = with lib; {
    description = "Verus -- an SMT-based verifier for Rust (prebuilt release, patched for NixOS)";
    homepage = "https://github.com/verus-lang/verus";
    license = with licenses; [ mit asl20 ];
    platforms = [ "x86_64-linux" ];
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
  };
}
