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

# JOS_QEMU_ACCEL picks the accelerator: tcg (default, software emulation) or
# kvm (hardware virtualization; -cpu host, since max under kvm means the host).
# JOS_QEMU_CPU overrides the cpu model either way.
case "${JOS_QEMU_ACCEL:-tcg}" in
    tcg) ACCEL=(-accel tcg); CPU="${JOS_QEMU_CPU:-max}" ;;
    kvm) ACCEL=(-accel kvm); CPU="${JOS_QEMU_CPU:-host}" ;;
    *) echo "run-qemu: JOS_QEMU_ACCEL must be tcg or kvm" >&2; exit 2 ;;
esac

# JOS_QEMU_RR=record or replay runs under deterministic record/replay into
# JOS_QEMU_RR_FILE: a recorded failure replays instruction for instruction.
# replay needs instruction counting and the cd image behind blkreplay, so its
# reads are part of the recording too; it only works under tcg.
DISK=(-cdrom "$ISO")
RR=()
if [ -n "${JOS_QEMU_RR:-}" ]; then
    case "$JOS_QEMU_RR" in
        record|replay) ;;
        *) echo "run-qemu: JOS_QEMU_RR must be record or replay" >&2; exit 2 ;;
    esac
    if [ "${JOS_QEMU_ACCEL:-tcg}" != tcg ]; then
        echo "run-qemu: record/replay needs JOS_QEMU_ACCEL=tcg" >&2
        exit 2
    fi
    RR_FILE="${JOS_QEMU_RR_FILE:?run-qemu: set JOS_QEMU_RR_FILE for record/replay}"
    RR=(-icount "shift=auto,rr=$JOS_QEMU_RR,rrfile=$RR_FILE")
    # a replay must boot the very image the recording read, and grub-mkrescue
    # output is not byte-stable, so the recording keeps its own copy.
    if [ "$JOS_QEMU_RR" = record ]; then
        cp "$ISO" "$RR_FILE.iso"
        sha256sum < "$KERNEL" > "$RR_FILE.kernel"
    elif ! sha256sum < "$KERNEL" | cmp -s - "$RR_FILE.kernel"; then
        echo "run-qemu: $RR_FILE recorded a different kernel than $KERNEL" >&2
        exit 2
    fi
    ISO="$RR_FILE.iso"
    DISK=(
        -drive "file=$ISO,if=none,id=iso,media=cdrom,readonly=on,snapshot=on"
        -drive "driver=blkreplay,if=none,image=iso,id=iso-rr"
        -device "ide-cd,drive=iso-rr"
    )
fi

# boot headless, bounded by a timeout so a wedged guest fails the test instead
# of hanging it (override with JOS_QEMU_TIMEOUT seconds). capture qemu's exit
# code: isa-debug-exit maps a guest write of N at port 0xf4 to a host exit of (N<<1)|1, so success (0x10) => 33.
set +e
timeout --foreground -k 5 "${JOS_QEMU_TIMEOUT:-120}" qemu-system-x86_64 \
    -machine q35 \
    "${ACCEL[@]}" \
    -cpu "$CPU" \
    -m 128M \
    "${DISK[@]}" \
    "${RR[@]}" \
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
# qemu itself exits 0 when the guest resets under -no-reboot (a triple fault),
# so a plain 0 means the kernel crashed, not that it passed.
if [ "$QEMU_EXIT" -eq 0 ]; then
    echo "run-qemu: guest reset without reporting a result (triple fault?)" >&2
    exit 1
fi
exit "$QEMU_EXIT"
