#!/usr/bin/env bash
# Assemble BootKernelExtensions.kc (fileset KC) for the XNU/QEMU bring-up.
#
#  -kext     real, linked kexts (code loaded into the KC)
#  -codeless Info.plist-only interface/KPI kexts (dependency resolution only)
#
# The com.apple.kpi.* interface kexts live as System.kext PlugIns; they must be
# present as codeless bundles so OSBundleLibraries deps of the real kexts resolve.
set -euo pipefail

# excuse the hardcoded values
DARWIN=/home/vali/development/darwin
KEXTS=$DARWIN/PureDarwin/build-install/System/Library/Extensions
KERNEL=$DARWIN/PureDarwin/build-install/System/Library/Kernels/kernel.debug
OUT=${1:-$DARWIN/xnu-loader/esp/EFI/BOOT/kernel}
KCB=$DARWIN/kc-builder/result/bin/kc-builder

CODELESS=()
for p in "$KEXTS"/System.kext/PlugIns/*.kext; do
  CODELESS+=( -codeless "$p" )
done

REAL=(
  -kext "$KEXTS/corecrypto.kext"
  -kext "$KEXTS/pthread.kext"
  -kext "$KEXTS/IOACPIFamily.kext"
  -kext "$KEXTS/IOPCIFamily.kext"
  -kext "$KEXTS/AppleAPIC.kext"
  -kext "$KEXTS/AppleI386GenericPlatform.kext"
  -kext "$KEXTS/AppleI386PCI.kext"
  -kext "$KEXTS/IOStorageFamily.kext"
  -kext "$KEXTS/IOATAFamily.kext"
  -kext "$KEXTS/IOATAFamily.kext/Contents/PlugIns/AppleIntelPIIXATA.kext"
  -kext "$KEXTS/IOATABlockStorage.kext"
  -kext "$KEXTS/ext4.kext"
  -kext "$KEXTS/HFSEncodings.kext"
  -kext "$KEXTS/hfs.kext"
  -kext "$KEXTS/AppleFileSystemDriver.kext"
)

set -x
"$KCB" -kernel "$KERNEL" "${REAL[@]}" "${CODELESS[@]}" -o "$OUT"
