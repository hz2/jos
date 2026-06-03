#!/usr/bin/env bash
# cargo runner for jos. invoked as: run-qemu.sh <path-to-kernel-elf>
# builds a grub multiboot2 rescue iso around the kernel and boots it headless
# under qemu. translates the isa-debug-exit success code (33) back to a shell
# exit of 0 so `cargo test` reports pass/fail correctly.
set -euo pipefail

KERNEL="$1"
BUILD_DIR="$(dirname "$KERNEL")/jos-iso"
ISO="$(dirname "$KERNEL")/jos.iso"

# assemble the grub iso tree: /boot/kernel.elf + /boot/grub/grub.cfg
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/boot/grub"
cp "$KERNEL" "$BUILD_DIR/boot/kernel.elf"
cat > "$BUILD_DIR/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "jos" {
    multiboot2 /boot/kernel.elf
    boot
}
EOF

# build the iso. -d i386-pc forces a bios (non-efi) image, which keeps the
# legacy text-mode vga at 0xb8000 live for the kernel. quiet the noisy output.
grub-mkrescue -d "$(dirname "$(command -v grub-mkrescue)")/../lib/grub/i386-pc" \
    -o "$ISO" "$BUILD_DIR" >/dev/null 2>&1 \
  || grub-mkrescue -o "$ISO" "$BUILD_DIR" >/dev/null 2>&1

# boot headless. capture qemu's exit code: isa-debug-exit maps a guest write of
# N at port 0xf4 to a host exit of (N<<1)|1, so success (0x10) => 33.
set +e
qemu-system-x86_64 \
    -machine q35 \
    -m 128M \
    -cdrom "$ISO" \
    -serial mon:stdio \
    -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot
QEMU_EXIT=$?
set -e

# 33 is our success sentinel; map it to 0. 35 (failed = 0x11) and anything else
# propagate as failure.
if [ "$QEMU_EXIT" -eq 33 ]; then
    exit 0
fi
exit "$QEMU_EXIT"
