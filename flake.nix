{
  description = "jos -- a capability-microkernel OS in Rust (reproducible build + verification toolchain)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ fenix.overlays.default ];
        };

        # Pinned nightly toolchain. `complete.withComponents` selects a recent nightly
        # where ALL requested components are present, then flake.lock pins the fenix input
        # so the exact nightly is reproducible across machines.
        #
        # build-std (for the custom bare-metal target) needs `rust-src`.
        # `bootimage` needs `llvm-tools` (llvm-objcopy) found via the sysroot.
        # Stage-0 verification needs `miri`.
        rustToolchain = fenix.packages.${system}.complete.withComponents [
          "cargo"
          "rustc"
          "rust-src"
          "rustfmt"
          "clippy"
          "llvm-tools"
          "miri"
          "rust-analyzer"
        ];

        # Verus and Kani ship prebuilt binaries (bundled Z3 / CBMC) that are dynamically
        # linked against a standard loader+glibc, which do not exist at the expected paths
        # on NixOS, so they are autoPatchelf'd onto the Nix runtime. Kept in a separate
        # `verify` shell so the default shell stays minimal and rock-solid.
        verus = pkgs.callPackage ./nix/verus.nix { };

        # Kani 0.67.0 pins its own nightly (nightly-2025-11-21, rustc 1.93). It
        # execs ./toolchain/bin/cargo and its kani-compiler links that toolchain's
        # librustc_driver. Build exactly that toolchain via fenix (cargo + rustc +
        # rust-src for build-std + rustc-dev for librustc_driver + std), and hand it
        # to the kani derivation, replacing what `cargo kani setup` would fetch.
        kaniToolchainOf = fenix.packages.${system}.toolchainOf {
          channel = "nightly";
          date = "2025-11-21";
          sha256 = "sha256-P39FCgpfDT04989+ZTNEdM/k/AE869JKSB4qjatYTSs=";
        };
        kaniToolchain = fenix.packages.${system}.combine [
          kaniToolchainOf.cargo
          kaniToolchainOf.rustc
          kaniToolchainOf.rust-src
          kaniToolchainOf.rustc-dev
          kaniToolchainOf.rust-std
          kaniToolchainOf.clippy
        ];
        kani = pkgs.callPackage ./nix/kani.nix { inherit kaniToolchain; };

        # Common runtime libs the patched verifier binaries link against.
        commonShellHook = ''
          # bootimage discovers llvm-tools via `rustc --print sysroot`; the fenix toolchain
          # places them under $sysroot/lib/rustlib/<host>/bin, so no extra setup is needed.
          export JOS_NIX_SHELL=1
        '';
      in
      {
        # Default shell: everything needed to build, boot, test, and Miri-check jos.
        devShells.default = pkgs.mkShell {
          name = "jos-dev";
          packages = [
            rustToolchain
            pkgs.qemu           # qemu-system-x86_64 for `cargo run` / `cargo test`
            pkgs.grub2          # grub-mkrescue: build the bootable multiboot2 iso
            pkgs.xorriso        # iso backend used by grub-mkrescue
            pkgs.cargo-binutils # rust-objcopy etc.
          ];
          shellHook = commonShellHook + ''
            echo "jos dev shell -- rustc $(rustc --version | cut -d' ' -f2), qemu $(qemu-system-x86_64 --version | head -1 | cut -d' ' -f4)"
            echo "  cargo build / cargo run / cargo test    (kernel under QEMU)"
            echo "  cargo miri test -p jos-core             (Stage 0 UB checks, once workspace split lands)"
            echo "  nix develop .#verify                    (adds Verus + Kani)"
          '';
        };

        # Verification shell: adds the heavyweight verifiers. May be slower to enter the
        # first time (fetches + patches the prebuilt release archives).
        devShells.verify = pkgs.mkShell {
          name = "jos-verify";
          packages = [
            rustToolchain
            pkgs.qemu
            pkgs.grub2
            pkgs.xorriso
            pkgs.cargo-binutils
            verus
            kani
          ];
          shellHook = commonShellHook + ''
            echo "jos verify shell -- adds verus + kani on top of the default toolchain"
            echo "  note: verus expects a rustup-managed toolchain 1.95.0; if missing, run:"
            echo "        rustup install 1.95.0-x86_64-unknown-linux-gnu"
          '';
        };

        packages = {
          inherit verus kani;
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
