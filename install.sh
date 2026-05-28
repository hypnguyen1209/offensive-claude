#!/bin/bash
# Install offensive-claude skills, agents, templates, workflows, commands, and presets into ~/.claude/
set -e

DEST="${CLAUDE_HOME:-$HOME/.claude}"
REPO="https://github.com/hypnguyen1209/offensive-claude"

echo "[*] Installing offensive-claude to $DEST"

# Clone or update
TMPDIR=$(mktemp -d)
git clone --depth 1 "$REPO" "$TMPDIR" 2>/dev/null

# Copy skills
mkdir -p "$DEST/skills" "$DEST/agents" "$DEST/templates" "$DEST/workflows" "$DEST/commands" "$DEST/presets"
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

# Copy templates
cp -r "$TMPDIR"/templates/* "$DEST/templates/"

# Copy workflows
cp -r "$TMPDIR"/workflows/* "$DEST/workflows/"

# Copy commands
cp -r "$TMPDIR"/commands/* "$DEST/commands/"

# Copy presets
cp -r "$TMPDIR"/presets/* "$DEST/presets/"

# Copy CLAUDE.md if not exists
if [ ! -f "$DEST/CLAUDE.md" ]; then
  cp "$TMPDIR/CLAUDE.md" "$DEST/CLAUDE.md"
else
  echo "[!] CLAUDE.md already exists, skipping (see $TMPDIR/CLAUDE.md)"
fi

# Cleanup
rm -rf "$TMPDIR"

echo "[+] Done! Installed:"
echo "    - 25 skills with Kill Chain metadata"
echo "    - 6 collaborative agents"
echo "    - 47 vulnerability references"
echo "    - 18 engagement templates (9 phases)"
echo "    - 7 workflow definitions"
echo "    - 12 orchestration commands (/engage.*)"
echo "    - 7 engagement presets"
echo ""
echo "    Run '/engage.init web-app' to start your first engagement."
