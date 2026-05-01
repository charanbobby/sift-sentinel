#!/usr/bin/env bash
# PreToolUse hook: block Edit / Write / MultiEdit on enforce-listed runtime
# files unless a fresh probe marker exists in .probes/.
#
# Enforce-list is read from .failfast.list at repo root, one glob pattern per
# line. Lines starting with # and blank lines are ignored. If .failfast.list
# does not exist, the gate is a no-op (project has not opted in).
#
# A probe marker is fresh when:
#   1. it exists, AND
#   2. its mtime is >= the target file's mtime (every new edit needs a probe), AND
#   3. its mtime is within the last 60 minutes.
#
# Run a probe with: scripts/probe.sh <target> -- <command>

set -euo pipefail

input="$(cat)"

# Tiny JSON extractors (avoid jq dep). Capture first match only.
tool_name="$(printf '%s' "$input" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
file_path="$(printf '%s' "$input" | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"

case "$tool_name" in
  Edit|Write|MultiEdit) ;;
  *) exit 0 ;;
esac

[ -n "$file_path" ] || exit 0

# Normalize windows backslashes.
fp="$(printf '%s' "$file_path" | tr '\\' '/')"

# Find repo root from the file's directory.
dir="$(dirname "$fp")"
repo_root="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$repo_root" ]; then
  exit 0
fi
repo_root="$(printf '%s' "$repo_root" | tr '\\' '/')"

cfg="$repo_root/.failfast.list"
[ -f "$cfg" ] || exit 0  # opt-in: no list, no enforcement

# Case-insensitive prefix strip (Windows drive-letter case mismatch).
fp_lower="$(printf '%s' "$fp" | tr '[:upper:]' '[:lower:]')"
root_lower="$(printf '%s' "$repo_root" | tr '[:upper:]' '[:lower:]')"
plen=${#root_lower}
if [ "${fp_lower:0:$plen}" = "$root_lower" ]; then
  rel="${fp:$plen}"
  rel="${rel#/}"
else
  rel="$fp"
fi

# Match rel against each pattern in .failfast.list.
shopt -s globstar nullglob 2>/dev/null || true
enforce=false
while IFS= read -r pattern || [ -n "$pattern" ]; do
  pattern="${pattern%%#*}"  # strip trailing comment
  pattern="${pattern#"${pattern%%[![:space:]]*}"}"  # ltrim
  pattern="${pattern%"${pattern##*[![:space:]]}"}"  # rtrim
  [ -z "$pattern" ] && continue
  if [[ $rel == $pattern ]]; then
    enforce=true
    break
  fi
done < "$cfg"

[ "$enforce" = "true" ] || exit 0

sanitized="$(printf '%s' "$rel" | tr '/' '_')"
marker="$repo_root/.probes/$sanitized.lastrun"

emit_block() {
  local reason="$1"
  cat >&2 <<MSG
FAIL-FAST GATE BLOCKED Edit/Write on $rel

Reason: $reason

Run a probe first, then retry:
  scripts/probe.sh $rel -- <your-probe-command>

Enforce-list source: .failfast.list (matched pattern: $pattern)
MSG
  exit 2
}

if [ ! -f "$marker" ]; then
  emit_block "no probe marker exists for $rel"
fi

now="$(date +%s)"
mtime_marker="$(stat -c %Y "$marker" 2>/dev/null || stat -f %m "$marker" 2>/dev/null || echo 0)"

if [ -f "$fp" ]; then
  mtime_file="$(stat -c %Y "$fp" 2>/dev/null || stat -f %m "$fp" 2>/dev/null || echo 0)"
  if [ "$mtime_marker" -lt "$mtime_file" ]; then
    emit_block "probe marker is older than the target file (file edited since last probe)"
  fi
fi

age=$(( now - mtime_marker ))
if [ "$age" -gt 3600 ]; then
  emit_block "probe marker is stale ($((age/60)) minutes old; max 60)"
fi

exit 0
