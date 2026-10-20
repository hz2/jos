#!/usr/bin/env bash
# cargo runner for jos. invoked as: run-qemu.sh <path-to-kernel-elf>
# builds a grub multiboot2 rescue iso around the kernel (and any boot modules)
# and boots it headless under qemu. translates the isa-debug-exit success code
# (33) back to a shell exit of 0 so `cargo test` reports pass/fail correctly.
set -euo pipefail

KERNEL="$1"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# every run builds its own iso tree, so concurrent runs never collide.
BUILD_DIR="$(mktemp -d "$(dirname "$KERNEL")/jos-iso.XXXXXX")"
ISO="$BUILD_DIR.iso"
cleanup() {
    if [ -z "${JOS_KEEP_ISO:-}" ]; then
        rm -rf "$BUILD_DIR" "$ISO"
    fi
}
trap cleanup EXIT

# JOS_MODULES lists boot modules, ';'-separated, each "path [args]": grub
# loads each with module2, and the kernel finds a module by the first word of
# its args (the root task is the one named "root"). left unset for the main
# kernel binary, it means: build user/ and boot the root task, with
# JOS_ROOT_ARGS (default "hello") after its name. set it empty to boot
# without modules.
MODULES="${JOS_MODULES-}"
if [ -z "${JOS_MODULES+set}" ] && [ "$(basename "$KERNEL")" = jos ]; then
    # a separate target dir: the cargo that invoked this runner may still hold
    # the lock on its own.
    USER_TARGET="$(cd "$(dirname "$KERNEL")/../.." && pwd)/user"
    (cd "$REPO/user" && CARGO_TARGET_DIR="$USER_TARGET" cargo build -q)
    MODULES="$USER_TARGET/x86_64-unknown-none/debug/root root ${JOS_ROOT_ARGS:-hello}"
fi

# assemble the grub iso tree: /boot/kernel.elf, the modules, /boot/grub/grub.cfg
mkdir -p "$BUILD_DIR/boot/grub"
cp "$KERNEL" "$BUILD_DIR/boot/kernel.elf"
MODULE_FILES=()
{
    echo 'set timeout=0'
    echo 'set default=0'
    echo 'menuentry "jos" {'
    echo '    multiboot2 /boot/kernel.elf'
    IFS=';' read -ra ENTRIES <<< "$MODULES"
    for entry in "${ENTRIES[@]}"; do
        [ -n "${entry// /}" ] || continue
        path="${entry%% *}"
        args="${entry#"$path"}"
        name="$(basename "$path")"
        cp "$path" "$BUILD_DIR/boot/$name"
        MODULE_FILES+=("$path")
        echo "    module2 /boot/$name$args"
    done
    echo '    boot'
    echo '}'
} > "$BUILD_DIR/boot/grub/grub.cfg"

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

# the kernel and every module, hashed together: what a recording booted.
inputs_hash() { cat "$KERNEL" "${MODULE_FILES[@]}" | sha256sum; }

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
        inputs_hash > "$RR_FILE.kernel"
    elif ! inputs_hash | cmp -s - "$RR_FILE.kernel"; then
        echo "run-qemu: $RR_FILE recorded a different kernel or modules" >&2
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
# of hanging it (JOS_QEMU_TIMEOUT seconds; 0 means no limit). JOS_QEMU_MEM,
# JOS_QEMU_SMP and JOS_QEMU_MACHINE pick the memory size, the cpu count, and
# the machine type. capture qemu's exit code: isa-debug-exit maps a guest write
# of N at port 0xf4 to a host exit of (N<<1)|1, so success (0x10) => 33.
set +e
timeout --foreground -k 5 "${JOS_QEMU_TIMEOUT:-120}" qemu-system-x86_64 \
    -machine "${JOS_QEMU_MACHINE:-q35}" \
    "${ACCEL[@]}" \
    -cpu "$CPU" \
    -m "${JOS_QEMU_MEM:-128M}" \
    -smp "${JOS_QEMU_SMP:-1}" \
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
