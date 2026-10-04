#!/usr/bin/env bash
# fast, tool-free style gate shared by the git hooks and the claude hooks.
# usage: scripts/check-style.sh FILE...
# checks: ascii-only text, no ai attribution phrases, and (for .rs) every
# `unsafe {` / `unsafe impl` has a SAFETY: comment in the comment block above.
# clippy's undocumented_unsafe_blocks lint is the authority; this is the
# instant early warning.

set -uo pipefail

status=0
report() {
    echo "check-style: $1" >&2
    status=1
}

for f in "$@"; do
    [ -f "$f" ] || continue
    case "$f" in
        *.rs|*.md|*.toml|*.sh|*.s|*.nix|*.json|*.yml) ;;
        *) continue ;;
    esac

    # non-ascii covers em dashes, smart quotes, and emojis in one rule.
    if hits=$(grep -nP '[^\x00-\x7F]' "$f"); then
        report "$f: non-ascii characters (no em dashes or emojis):"
        echo "$hits" | head -5 >&2
    fi

    # the hook scripts define this rule, so they are exempt from it.
    case "$f" in *scripts/check-style.sh|*.githooks/*|*.claude/hooks/*) attribution_exempt=1 ;; *) attribution_exempt=0 ;; esac
    if [ $attribution_exempt -eq 0 ] && hits=$(grep -niE 'co-authored-by: *claude|generated (with|by) (claude|ai)|as an ai' "$f"); then
        report "$f: ai attribution phrase:"
        echo "$hits" | head -5 >&2
    fi

    if [[ "$f" == *.rs ]]; then
        # an unsafe block or impl needs SAFETY: in the contiguous comment block
        # (or attributes) above it, or on the same line. one comment may cover a
        # run of one-line unsafe statements or a `let x =` continuation. skips
        # `unsafe fn` and `unsafe extern`, which
        # need a `# Safety` doc section instead.
        missing=$(awk '
            { line[NR] = $0 }
            /(^|[^a-z_])unsafe[ ]*(\{|impl)/ && !/unsafe[ ]+(fn|extern)/ && !/^[ ]*\/\// {
                ok = ($0 ~ /SAFETY:/)
                for (i = NR - 1; i > 0 && (line[i] ~ /^[ ]*(\/\/|#\[)/ || line[i] ~ /unsafe[ ]*\{.*\};?[ ]*$/ || line[i] ~ /=[ ]*$/); i--)
                    if (line[i] ~ /SAFETY:/) ok = 1
                if (!ok) printf "%d: %s\n", NR, $0
            }' "$f")
        if [ -n "$missing" ]; then
            report "$f: unsafe without a SAFETY: comment just above:"
            echo "$missing" | head -5 >&2
        fi
    fi
done

exit $status
