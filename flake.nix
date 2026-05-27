# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
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
      nixpkgs,
      flake-utils,
      rust-overlay,
      treefmt-nix,
      ...
    }:
    let
      eachSystem = flake-utils.lib.eachSystem;
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
    in
    eachSystem systems (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit overlays system;
        };

        rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          targets = [
            "aarch64-unknown-linux-musl"
            "x86_64-unknown-linux-musl"
          ];
        };
        aarch64LinuxMuslCc = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;
        x86_64LinuxMuslCc = pkgs.pkgsCross.musl64.stdenv.cc;
        treefmt = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
      in
      {
        formatter = treefmt.config.build.wrapper;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            aarch64LinuxMuslCc
            x86_64LinuxMuslCc

            # Required for bindgen
            llvmPackages.libclang
            # openshell-prover system dependencies
            z3
            pkg-config
          ];
          env = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            CC_aarch64_unknown_linux_musl = "${aarch64LinuxMuslCc}/bin/${aarch64LinuxMuslCc.targetPrefix}cc";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${aarch64LinuxMuslCc}/bin/${aarch64LinuxMuslCc.targetPrefix}cc";
            CC_x86_64_unknown_linux_musl = "${x86_64LinuxMuslCc}/bin/${x86_64LinuxMuslCc.targetPrefix}cc";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${x86_64LinuxMuslCc}/bin/${x86_64LinuxMuslCc.targetPrefix}cc";
          };
        };
      }
    );
}
