# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      crate2nix,
      flake-utils,
      nixpkgs,
      rust-overlay,
      treefmt-nix,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
          ];
        };
        lib = pkgs.lib;
        mkOpenShellPackages = pkgs: args: pkgs.callPackage ./nix/pkgs args;
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        shellPackages = with pkgs; [
          rustToolchain
          # Required to find packages
          pkg-config
          # Required for bindgen generation.
          llvmPackages.libclang
          # system dependency for openshell-prover
          z3
        ];
        shellEnv = {
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
        cargoNixSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./.cargo
            ./Cargo.lock
            ./Cargo.toml
            ./crates
            ./providers
            ./proto
          ];
        };
        generatedCargoNix = crate2nix.tools.${system}.generatedCargoNix {
          name = "openshell";
          src = cargoNixSrc;
          cargo = rustToolchain;
        };
        crateOverrides = pkgs.callPackage ./nix/crate-overrides.nix { };
        cargoNix = pkgs.callPackage generatedCargoNix {
          defaultCrateOverrides = pkgs.defaultCrateOverrides // crateOverrides;
          buildRustCrateForPkgs =
            pkgs:
            pkgs.buildRustCrate.override {
              rustc = rustToolchain;
              cargo = rustToolchain;
            };
        };
        releaseCrates = lib.mapAttrs' (
          name: crate: lib.nameValuePair "${name}-release" crate.build
        ) cargoNix.workspaceMembers;
        openshellPackages = mkOpenShellPackages pkgs {
          openshellSandbox = releaseCrates."openshell-sandbox-release";
        };
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
      in
      {
        devShells = {
          default = pkgs.mkShell {
            packages = shellPackages;

            env = shellEnv;
          };
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          vm = pkgs.mkShell {
            packages =
              shellPackages
              ++ (with pkgs; [
                e2fsprogs
                nftables
                qemu
                zstd
              ]);

            env = shellEnv // {
              OPENSHELL_VM_RUNTIME_COMPRESSED_DIR = "${openshellPackages.vmRuntimeCompressed}";
            };
          };
        };

        packages = {
          all = cargoNix.allWorkspaceMembers;
        }
        // releaseCrates
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          inherit (openshellPackages) vmRuntimeCompressed;
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
