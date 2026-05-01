#!/usr/bin/env bash
# One-shot installer for the fail-fast hooks on a fresh checkout.
#
# What it does:
#   1. Installs .git/hooks/pre-commit (calls scripts/pre-commit-fail-fast.sh).
#   2. Reminds the user to add the PreToolUse block to their local
#      .claude/settings.json (which is gitignored).
#
# Run:  bash scripts/install-hooks.sh

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cat > .git/hooks/pre-commit <<'EOF'
#!/usr/bin/env bash
# Local stub. Real logic in scripts/pre-commit-fail-fast.sh (tracked).
exec bash "$(git rev-parse --show-toplevel)/scripts/pre-commit-fail-fast.sh" "$@"
EOF
chmod +x .git/hooks/pre-commit
chmod +x scripts/probe.sh scripts/fail-fast-gate.sh scripts/pre-commit-fail-fast.sh

echo "[install-hooks] git pre-commit installed."
echo ""
echo "[install-hooks] To enable the Claude PreToolUse gate (gate when I edit"
echo "                runtime files), append this to .claude/settings.json"
echo "                under hooks:"
echo ""
cat <<'EOF'
    "PreToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "bash scripts/fail-fast-gate.sh",
            "timeout": 10
          }
        ]
      }
    ]
EOF
echo ""
echo "[install-hooks] done."
