#!/bin/bash
# Install offensive-claude skills and agents into ~/.claude/
set -e

DEST="${CLAUDE_HOME:-$HOME/.claude}"
REPO="https://github.com/hypnguyen1209/offensive-claude"

echo "[*] Installing offensive-claude to $DEST"

# Clone or update
TMPDIR=$(mktemp -d)
git clone --depth 1 "$REPO" "$TMPDIR" 2>/dev/null

# Copy skills
mkdir -p "$DEST/skills" "$DEST/agents"
for dir in "$TMPDIR"/skills/*/; do
  skill_name=$(basename "$dir")
  if [ "$skill_name" = "references" ]; then
    cp -r "$dir" "$DEST/skills/references"
  elif [ -f "$dir/SKILL.md" ]; then
    mkdir -p "$DEST/skills/$skill_name"
    cp "$dir/SKILL.md" "$DEST/skills/$skill_name/SKILL.md"
  fi
done

# Copy agents
cp "$TMPDIR"/agents/*.md "$DEST/agents/"

# Copy CLAUDE.md if not exists
if [ ! -f "$DEST/CLAUDE.md" ]; then
  cp "$TMPDIR/CLAUDE.md" "$DEST/CLAUDE.md"
else
  echo "[!] CLAUDE.md already exists, skipping (see $TMPDIR/CLAUDE.md)"
fi

# Cleanup
rm -rf "$TMPDIR"

echo "[+] Done! Installed:"
echo "    - 25 skills"
echo "    - 6 agents"
echo "    - 47 vulnerability references"
echo ""
echo "    Skills are active globally for all projects."
