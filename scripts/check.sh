#!/usr/bin/env bash
# every check jos runs, defined once. the git hooks, ci, and any local agent
# hooks all call this script.
#
# usage: scripts/check.sh <gate> [arg]
#   style [files]   ascii, no ai attribution, SAFETY on every unsafe
#   clippy          clippy -D warnings on both crates
#   test            jos-core unit + simulation tests (host)
#   miri            undefined-behavior check of jos-core
#   kani [harness]  bounded proofs (all, or one harness)
#   verus           verus proof module (jos-core/src/proof.rs)
#   qemu [test]     boot kernel tests under qemu (all, or one by name)
#   fast            style + clippy + test (pre-commit)
#   ci              fast + miri + kani + qemu (pre-push, ci)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# re-run inside the dev shell unless we are already in it.
if [ -z "${JOS_NIX_SHELL:-}" ]; then
    exec nix develop --command "$0" "$@"
fi

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
fast() { style; clippy; test; }
ci() { fast; miri; kani; qemu; }

if [ $# -eq 0 ]; then
    sed -n '5,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

gate=$1
shift
case "$gate" in
    style|clippy|test|miri|kani|verus|qemu|fast|ci)
        echo "[check] $gate $*"
        "$gate" "$@"
        ;;
    *)
        echo "check.sh: unknown gate '$gate'" >&2
        exit 2
        ;;
esac
