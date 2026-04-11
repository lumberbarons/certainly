# Running Certainly on Mac OS 9 — Emulator Setup

Build the library and examples first (see the main README), then use one of
the two emulators below. Both expect a `vm/` directory at the repo root
(gitignored) containing the ROM and disk images described below.

---

## SheepShaver (recommended)

SheepShaver provides shared clipboard, seamless mouse capture, and boots
pre-built disk images directly — no OS installation step required.

### One-time setup

1. **Build SheepShaver from source** (native arm64 on Apple Silicon):

   ```sh
   git clone https://github.com/kanjitalk755/macemu.git
   cd macemu/SheepShaver/src/MacOSX
   xcodebuild -project SheepShaver.xcodeproj -configuration Release
   ```

   The binary lands in `build/Release/SheepShaver.app`. The pre-built
   `/Applications/SheepShaver.app` is x86-only and requires Rosetta on
   Apple Silicon.

2. **Obtain an Old World Mac ROM** (a 4 MB file, often named
   `mac_oldworld_rom4mb.rom`). This is Apple's property; you'll need to
   source it yourself. Place it at `vm/rom.bin`.

3. **Obtain a Mac OS 9 disk image** — a raw HFS image, roughly 200–300 MB.
   Mac OS 9 is also Apple's property; you'll need to source it yourself,
   ideally from a legitimately owned install CD or an existing Mac.
   Place it at `vm/macos9.img`.

### Launch

```sh
./run-sheepshaver.sh
```

The script generates a prefs file, mounts the example `.dsk` images from
`build/examples/`, and starts SheepShaver with SLiRP networking.

---

## QEMU (alternative)

QEMU uses OpenBIOS instead of a Mac ROM, so it requires no proprietary
firmware — but it does require a fresh Mac OS 9 install from an ISO, and
lacks SheepShaver's clipboard and mouse integration.

### One-time setup

1. Install QEMU:

   ```sh
   brew install qemu
   ```

2. Obtain a Mac OS 9.2.2 install CD ISO. Place it at `vm/MacOS9.iso`.

3. Create a virtual disk:

   ```sh
   qemu-img create -f qcow2 vm/macos9-qemu.qcow2 2G
   ```

4. Install the OS:

   ```sh
   ./run-macos9.sh install
   ```

   Inside the installer: open Drive Setup, initialize the hard drive as
   "Mac OS Extended", then run the Mac OS 9 installer.

### Launch

```sh
./run-macos9.sh
```

---

## Networking (both emulators)

Both scripts provide NAT networking via SLiRP. Inside Mac OS 9:

1. Open the **TCP/IP** control panel.
2. Set **Connect via** to **Ethernet**.
3. Set **Configure** to **Using DHCP Server**.
4. Close and save.

The guest can then reach the internet through the host's connection. Example
disk images appear on the Mac OS 9 desktop; open them to run the apps.
