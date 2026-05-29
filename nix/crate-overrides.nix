{
  lib,
  llvmPackages,
  pkg-config,
  runCommand,
  z3,
}:

{
  "openshell-core" = prev: {
    src = runCommand "openshell-core-src" { } ''
      mkdir -p "$out/crates" "$out/proto"
      cp -R ${prev.src} "$out/crates/openshell-core"
      cp -R ${../proto}/. "$out/proto/"
    '';
    workspace_member = "crates/openshell-core";
  };
  "openshell-providers" = prev: {
    src = runCommand "openshell-providers-src" { } ''
      mkdir -p "$out/crates" "$out/providers"
      cp -R ${prev.src} "$out/crates/openshell-providers"
      cp -R ${../providers}/. "$out/providers/"
    '';
    workspace_member = "crates/openshell-providers";
  };
  "protobuf-src" = _: {
    postConfigure = ''
      build_dir="$(pwd)/target/build/protobuf-src.out/install"
      install_dir="$lib/lib/protobuf-src.out/install"

      export INSTALL_DIR="$install_dir"

      substituteInPlace target/env \
        --replace "$build_dir" "$install_dir"
    '';
  };
  "z3-sys" = _: {
    nativeBuildInputs = [
      pkg-config
      llvmPackages.libclang
    ];
    buildInputs = [
      z3
    ];
    LIBCLANG_PATH = "${lib.getLib llvmPackages.libclang}/lib";
  };
}
