#!/usr/bin/env bash
# Pre-commit fail-fast gate body.
#
# Hooked in via .git/hooks/pre-commit (which is local-only). To install on a
# fresh checkout: bash scripts/install-hooks.sh
#
# For every staged file matched by a pattern in .failfast.list, require a
# fresh probe marker in .probes/. If any are missing or stale, block commit.
#
# Bypass: git commit --no-verify (discouraged; document why if you do).

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cfg="$repo_root/.failfast.list"

# Opt-in: no list, no enforcement.
[ -f "$cfg" ] || exit 0

shopt -s globstar nullglob 2>/dev/null || true

matches_any_pattern() {
  local f="$1"
  local pattern
  while IFS= read -r pattern || [ -n "$pattern" ]; do
    pattern="${pattern%%#*}"
    pattern="${pattern#"${pattern%%[![:space:]]*}"}"
    pattern="${pattern%"${pattern##*[![:space:]]}"}"
    [ -z "$pattern" ] && continue
    if [[ $f == $pattern ]]; then
      return 0
    fi
  done < "$cfg"
  return 1
}

fail=false

while IFS= read -r f; do
  [ -z "$f" ] && continue
  matches_any_pattern "$f" || continue

  sanitized="$(printf '%s' "$f" | tr '/' '_')"
  marker="$repo_root/.probes/$sanitized.lastrun"

  if [ ! -f "$marker" ]; then
    echo "[pre-commit] BLOCKED: no probe marker for $f" >&2
    echo "             run: scripts/probe.sh $f -- <your-probe-command>" >&2
    fail=true
    continue
  fi

  abs="$repo_root/$f"
  mtime_marker="$(stat -c %Y "$marker" 2>/dev/null || stat -f %m "$marker" 2>/dev/null || echo 0)"
  mtime_file="$(stat -c %Y "$abs" 2>/dev/null || stat -f %m "$abs" 2>/dev/null || echo 0)"

  if [ "$mtime_marker" -lt "$mtime_file" ]; then
    echo "[pre-commit] BLOCKED: probe marker for $f is older than the file" >&2
    echo "             run a fresh probe: scripts/probe.sh $f -- <your-probe-command>" >&2
    fail=true
  fi
done < <(git diff --cached --name-only --diff-filter=ACM)

if [ "$fail" = "true" ]; then
  echo "" >&2
  echo "[pre-commit] commit blocked. Bypass: git commit --no-verify (only if necessary)." >&2
  exit 1
fi

exit 0
