#!/bin/bash
# Launch Mac OS 9 in QEMU with networking and our test apps
#
# Usage: ./run-macos9.sh [install]
#
# QEMU boots Mac OS 9 from a qcow2 disk image that you install once.
# SheepShaver (run-sheepshaver.sh) is the recommended emulator — it has
# shared clipboard, seamless mouse capture, and works with pre-built
# infinite-mac disk images. Use this script if you prefer QEMU or don't
# have a Mac ROM file.
#
# First-time setup:
#   1. Obtain a Mac OS 9.2.2 install CD ISO
#   2. Create a disk image:
#        qemu-img create -f qcow2 vm/macos9-qemu.qcow2 2G
#   3. Install the OS:
#        ./run-macos9.sh install
#      Boot from CD, open Drive Setup, initialize the hard drive as
#      "Mac OS Extended", then run the installer.
#   4. After install completes, boot normally:
#        ./run-macos9.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VM_DIR="$SCRIPT_DIR/vm"
BUILD_DIR="$SCRIPT_DIR/build"

DISK="$VM_DIR/macos9-qemu.qcow2"
ISO="$VM_DIR/MacOS9.iso"

if [ ! -f "$DISK" ]; then
    echo "Error: QEMU disk image not found at $DISK"
    echo "Create one with: qemu-img create -f qcow2 $DISK 2G"
    exit 1
fi

# --- Example disk images ---
EXTRA_DRIVES=""
for dsk in \
    "$BUILD_DIR/examples/simple_get/SimpleGet.dsk" \
    "$BUILD_DIR/examples/postman/Postman.dsk"; do
    if [ -f "$dsk" ]; then
        EXTRA_DRIVES="$EXTRA_DRIVES -drive file=$dsk,format=raw,media=disk"
    fi
done

# --- Install mode vs normal boot ---
if [ "${1:-}" = "install" ]; then
    if [ ! -f "$ISO" ]; then
        echo "Error: Install ISO not found at $ISO"
        echo "Place a Mac OS 9 install CD ISO there."
        exit 1
    fi
    echo "Starting Mac OS 9 installer in QEMU..."
    echo "  1. Open Drive Setup and initialize the hard drive"
    echo "  2. Run the Mac OS 9 installer"
    echo "  3. After install, quit QEMU and run: ./run-macos9.sh"
    echo ""
    exec qemu-system-ppc \
        -M mac99,via=pmu \
        -cpu g4 \
        -m 512 \
        -hda "$DISK" \
        -cdrom "$ISO" \
        -boot d \
        -g 1024x768x32 \
        -device usb-mouse \
        -device usb-kbd \
        -display cocoa
fi

echo "Starting Mac OS 9 in QEMU..."
echo "  - Example .dsk files mounted (if built)"
echo "  - Networking: NAT (internet access via your Mac's connection)"
echo ""
echo "Inside Mac OS 9:"
echo "  1. Open TCP/IP control panel"
echo "  2. Set 'Connect via' to 'Ethernet'"
echo "  3. Set 'Configure' to 'Using DHCP Server'"
echo "  4. Close and save"
echo ""

exec qemu-system-ppc \
    -M mac99,via=pmu \
    -cpu g4 \
    -m 512 \
    -boot c \
    -hda "$DISK" \
    $EXTRA_DRIVES \
    -g 1024x768x32 \
    -device usb-mouse \
    -device usb-kbd \
    -display cocoa \
    -net nic,model=sungem \
    -net user
