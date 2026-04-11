#!/bin/bash
# Launch Mac OS 9 in SheepShaver with networking and our test apps
#
# Usage: ./run-sheepshaver.sh
#
# Prerequisites (one-time setup):
#   1. Build SheepShaver from source for native arm64:
#        git clone https://github.com/kanjitalk755/macemu.git
#        cd macemu/SheepShaver/src/MacOSX
#        xcodebuild -project SheepShaver.xcodeproj -configuration Release
#      The built app lands in build/Release/SheepShaver.app
#
#   2. Obtain an Old World Mac ROM (4 MB). Apple's property — source it
#      yourself.
#      Place it at: vm/rom.bin
#
#   3. Obtain a Mac OS 9 disk image (raw HFS, ~200-300 MB). Apple's
#      property — source it yourself, ideally from a legitimately owned
#      install CD or an existing Mac.
#      Place it at: vm/macos9.img
#
# The vm/ directory is gitignored. See README.md for full details.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VM_DIR="$SCRIPT_DIR/vm"
BUILD_DIR="$SCRIPT_DIR/build"

ROM="$VM_DIR/rom.bin"
DISK="$VM_DIR/macos9.img"
SCRATCH="$VM_DIR/scratch.img"

# --- Locate SheepShaver binary ---
# Prefer a source build (native arm64) over /Applications (x86-only).
SHEEPSHAVER=""
CANDIDATES=(
    "$HOME/Downloads/macemu/SheepShaver/src/MacOSX/build/Release/SheepShaver.app/Contents/MacOS/SheepShaver"
    "/Applications/SheepShaver.app/Contents/MacOS/SheepShaver"
)
for candidate in "${CANDIDATES[@]}"; do
    if [ -x "$candidate" ]; then
        SHEEPSHAVER="$candidate"
        break
    fi
done

if [ -z "$SHEEPSHAVER" ]; then
    echo "Error: SheepShaver not found."
    echo "Build from source or install to /Applications. See README.md."
    exit 1
fi

echo "Using: $SHEEPSHAVER"

# --- Check prerequisites ---
if [ ! -f "$ROM" ]; then
    echo "Error: ROM not found at $ROM"
    echo "Place an Old World Mac ROM (4 MB) there. See README.md."
    exit 1
fi

if [ ! -f "$DISK" ]; then
    echo "Error: Mac OS 9 disk image not found at $DISK"
    echo "Place a raw HFS image there. See README.md."
    exit 1
fi

# --- Make a writable copy of the OS disk (preserve the original) ---
WORK_DISK="/tmp/certainly-macos9.img"
if [ ! -f "$WORK_DISK" ]; then
    echo "Copying Mac OS 9 disk image (one-time)..."
    cp "$DISK" "$WORK_DISK"
fi

# --- Create scratch disk for installing apps (2 GB) ---
WORK_SCRATCH="/tmp/certainly-scratch.img"
if [ -f "$SCRATCH" ] && [ ! -f "$WORK_SCRATCH" ]; then
    echo "Copying scratch disk (one-time)..."
    cp "$SCRATCH" "$WORK_SCRATCH"
fi
if [ ! -f "$WORK_SCRATCH" ]; then
    echo "Creating 2 GB scratch disk (one-time)..."
    echo "  After boot, open Drive Setup and initialize it as Mac OS Extended."
    dd if=/dev/zero of="$WORK_SCRATCH" bs=1m count=2048 2>/dev/null
fi

# --- Write prefs file ---
# SheepShaver always reads ~/.sheepshaver_prefs and merges it with CLI
# flags, so we must write a complete prefs file to avoid duplicate disks.
PREFS="$HOME/.sheepshaver_prefs"

{
    echo "rom $ROM"
    echo "disk $WORK_DISK"
    echo "disk $WORK_SCRATCH"
    for dsk in \
        "$BUILD_DIR/examples/simple_get/SimpleGet.dsk" \
        "$BUILD_DIR/examples/postman/Postman.dsk" \
        "$SCRIPT_DIR/../clawssic/build/Clawssic.dsk"; do
        if [ -f "$dsk" ]; then
            echo "disk $dsk"
        fi
    done
    cat <<'EOF'
ramsize 536870912
screen win/800/600
nosound true
ignoresegv true
idlewait true
jit false
ether slirp
frameskip 1
gfxaccel true
EOF
} > "$PREFS"

echo "Starting Mac OS 9 in SheepShaver..."
echo "  - Scratch disk mounted (2 GB, initialize with Drive Setup on first boot)"
echo "  - Example .dsk files mounted (if built)"
echo "  - Networking: SLiRP NAT (internet access via your Mac's connection)"
echo ""
echo "Inside Mac OS 9:"
echo "  1. Open TCP/IP control panel"
echo "  2. Set 'Connect via' to 'Ethernet'"
echo "  3. Set 'Configure' to 'Using DHCP Server'"
echo "  4. Close and save"
echo "  5. Open an example disk on the desktop and double-click the app"
echo ""

exec "$SHEEPSHAVER"
