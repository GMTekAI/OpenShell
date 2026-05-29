{
  gvproxy,
  lib,
  openshellLibkrun,
  openshellLibkrunfw,
  openshellSandbox,
  runCommand,
  stdenv,
  umoci,
  zstd,
}:

assert stdenv.hostPlatform.isLinux;

runCommand "openshell-vm-runtime-compressed"
  {
    nativeBuildInputs = [ zstd ];
  }
  ''
    mkdir -p "$out"

    zstd -19 -T0 -f -q -o "$out/libkrun.so.zst" \
      "${lib.getLib openshellLibkrun}/lib/libkrun.so"
    zstd -19 -T0 -f -q -o "$out/libkrunfw.so.5.zst" \
      "${lib.getLib openshellLibkrunfw}/lib64/libkrunfw.so.5"
    zstd -19 -T0 -f -q -o "$out/gvproxy.zst" \
      "${gvproxy}/bin/gvproxy"
    zstd -19 -T0 -f -q -o "$out/umoci.zst" \
      "${umoci}/bin/umoci"
    zstd -19 -T0 -f -q -o "$out/openshell-sandbox.zst" \
      "${openshellSandbox}/bin/openshell-sandbox"

    chmod 0644 "$out"/*.zst
  ''
