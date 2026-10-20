#!/usr/bin/env bash
# every check jos runs, defined once. the git hooks, ci, and any local agent
# hooks all call this script.
#
# usage: scripts/check.sh <gate> [arg]
#   style [files]   ascii, no ai attribution, SAFETY on every unsafe
#   clippy          clippy -D warnings on jos-core, the kernel, and user/
#   test            jos-core unit + simulation tests (host)
#   miri            undefined-behavior check of jos-core
#   kani [harness]  bounded proofs (all, or one harness)
#   verus           verus proof module (jos-core/src/proof.rs)
#   qemu [test]     boot kernel tests under qemu (all, or one by name)
#   qemu-kvm [test] the same under kvm instead of tcg, skipped without /dev/kvm
#   boot            the real kernel booting the real root task in test mode,
#                   under tcg and (when /dev/kvm is usable) kvm
#   fast            style + clippy + test (pre-commit)
#   ci              fast + miri + kani + qemu + qemu-kvm + boot (pre-push to main, ci)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# re-run inside the dev shell unless we are already in it.
if [ -z "${JOS_NIX_SHELL:-}" ]; then
    exec nix develop --command "$0" "$@"
fi

# the target dir of the user/ workspace: its own, next to the kernel's, so a
# build started from the qemu runner never waits on the cargo that runs it.
user_target() { echo "${CARGO_TARGET_DIR:-$PWD/target}/user"; }

style() {
    if [ $# -eq 0 ]; then
        mapfile -t files < <(git ls-files -co --exclude-standard)
        set -- "${files[@]}"
    fi
    scripts/check-style.sh "$@"
}
clippy() {
    cargo clippy -q -p jos-core --all-targets -- -D warnings
    (cd kernel && cargo clippy -q --all-targets -- -D warnings)
    (cd user && CARGO_TARGET_DIR="$(user_target)" cargo clippy -q -- -D warnings)
}
test() { cargo test -q -p jos-core; }
miri() { cargo miri test -q -p jos-core; }
kani() {
    nix develop .#verify --command cargo kani -p jos-core ${1:+--harness "$1"}
}
verus() {
    nix develop .#verify --command bash -c \
        'verus --crate-type lib --edition 2024 -L "$VERUS_LIB_DIR" --verify-module proof jos-core/src/lib.rs'
}
qemu() {
    if [ $# -eq 0 ]; then
        (cd kernel && cargo test --all-targets)
    else
        (cd kernel && cargo test --test "$1")
    fi
}
qemu-kvm() {
    # timing differs a lot between accelerators, so a test that only passes
    # under one of them is caught here.
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        echo "[check] qemu-kvm: no usable /dev/kvm, skipped"
        return 0
    fi
    JOS_QEMU_ACCEL=kvm qemu "$@"
}
boot() {
    # the production path end to end: the real kernel binary loads the real
    # root task from its boot module, and the root task's self-test decides
    # the exit code.
    (cd kernel && cargo build -q)
    (cd user && CARGO_TARGET_DIR="$(user_target)" cargo build -q)
    local kernel="${CARGO_TARGET_DIR:-$PWD/target}/x86_64-jos/debug/jos"
    local root="$(user_target)/x86_64-unknown-none/debug/root"
    JOS_MODULES="$root root test" scripts/run-qemu.sh "$kernel"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        JOS_QEMU_ACCEL=kvm JOS_MODULES="$root root test" scripts/run-qemu.sh "$kernel"
    else
        echo "[check] boot: no usable /dev/kvm, kvm run skipped"
    fi
}
fast() { style; clippy; test; }
ci() { fast; miri; kani; qemu; qemu-kvm; boot; }

if [ $# -eq 0 ]; then
    sed -n '5,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

gate=$1
shift
case "$gate" in
    style|clippy|test|miri|kani|verus|qemu|qemu-kvm|boot|fast|ci)
        echo "[check] $gate $*"
        "$gate" "$@"
        ;;
    *)
        echo "check.sh: unknown gate '$gate'" >&2
        exit 2
        ;;
esac
