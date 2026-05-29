{
  libkrunfw,
  stdenv,
  variant ? null,
}:

let
  base = libkrunfw.override {
    inherit variant;
  };
  guestArch = stdenv.hostPlatform.parsed.cpu.name;
  kernelArch =
    if stdenv.hostPlatform.system == "aarch64-linux" then
      "arm64"
    else if stdenv.hostPlatform.system == "x86_64-linux" then
      "x86"
    else
      throw "openshell libkrunfw is only packaged for Linux";
in
base.overrideAttrs (old: {
  pname = "openshell-libkrunfw";

  # Merge the openshell configuration with the current Kernel configuration.
  postPatch = (old.postPatch or "") + ''
    cp ${../../crates/openshell-driver-vm/runtime/kernel/openshell.kconfig} openshell.kconfig

    kernel_sources="$(mktemp -d)"
    tar -xf ${old.kernelSrc} -C "$kernel_sources" --strip-components=1

    ARCH="${kernelArch}" KCONFIG_CONFIG="$PWD/config-libkrunfw_${guestArch}" \
      "$kernel_sources/scripts/kconfig/merge_config.sh" \
      -m -O "$kernel_sources" \
      "$PWD/config-libkrunfw_${guestArch}" \
      openshell.kconfig

    rm -rf "$kernel_sources"
  '';
})
