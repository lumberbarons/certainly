#!/bin/bash
# Launch Mac OS 9.2.2 in QEMU with networking and our test apps
# 
# Usage: ./run-macos9.sh
#
# This opens a QEMU window running Mac OS 9 with:
#   - NAT networking (can reach the internet)
#   - HelloToolbox.dsk and SimpleGet.dsk as extra disks

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MACOS9_SRC="$HOME/Development/Vintage/infinite-mac/Images/Mac OS 9.2.2 HD.dsk"
MACOS9_IMG="/tmp/macos9-certainly.img"

# Make a writable copy of the Mac OS 9 disk (QEMU needs write access)
if [ ! -f "$MACOS9_IMG" ]; then
    echo "Copying Mac OS 9 disk image (one-time)..."
    cp "$MACOS9_SRC" "$MACOS9_IMG"
fi

echo "Starting Mac OS 9.2.2 in QEMU..."
echo "  - HelloToolbox.dsk and SimpleGet.dsk mounted as extra drives"
echo "  - Networking: NAT (internet access via your Mac's connection)"
echo ""
echo "After Mac OS 9 boots:"
echo "  1. Open TCP/IP control panel"
echo "  2. Set 'Connect via' to 'Ethernet'"  
echo "  3. Set 'Configure' to 'Using DHCP Server'"
echo "  4. Close and save"
echo "  5. Open the HelloToolbox or SimpleGet disk on the desktop"
echo "  6. Double-click the app"
echo ""

qemu-system-ppc \
    -M mac99,via=pmu \
    -cpu g4 \
    -m 512 \
    -boot c \
    -drive file="$MACOS9_IMG",format=raw,media=disk \
    -drive file="$SCRIPT_DIR/build/examples/hello_toolbox/HelloToolbox.dsk",format=raw,media=disk \
    -drive file="$SCRIPT_DIR/build/examples/simple_get/SimpleGet.dsk",format=raw,media=disk \
    -prom-env "boot-device=hd:,\\:tbxi" \
    -display cocoa \
    -net nic,model=sungem \
    -net user
