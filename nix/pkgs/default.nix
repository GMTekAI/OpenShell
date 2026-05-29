{
  callPackage,
  lib,
  openshellSandbox,
  stdenv,
}:

let
  openshellLibkrunfw = callPackage ./libkrunfw.nix { };
  openshellLibkrun = callPackage ./libkrun.nix {
    inherit openshellLibkrunfw;
  };
in
lib.optionalAttrs stdenv.hostPlatform.isLinux {
  inherit openshellLibkrun openshellLibkrunfw;

  vmRuntimeCompressed = callPackage ./vm-runtime.nix {
    inherit openshellLibkrun openshellLibkrunfw openshellSandbox;
  };
}
