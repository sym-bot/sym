#!/bin/bash
# SYM — Setup for Claude Code
#
# Installs:
#   1. sym-daemon (persistent physical mesh node, launchd LaunchAgent)
#   2. MCP server for Claude Code (virtual node, connects to daemon via IPC)
#   3. Auto-approves sym_mood tool
#   4. CLAUDE.md instructions for autonomous mood detection
#
# Usage:
#   npx @sym-bot/sym setup        # or
#   ./bin/setup-claude.sh [project-dir]

set -e

SYM_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MCP_SERVER="$SYM_DIR/integrations/claude-code/mcp-server.js"
DAEMON_SCRIPT="$SYM_DIR/bin/sym-daemon.js"

echo ""
echo "  SYM Setup for Claude Code"
echo "  ========================="
echo ""

# ── Step 1: Configure relay ─────────────────────────────────

RELAY_ENV="$HOME/.sym/relay.env"
mkdir -p "$HOME/.sym"

if [ -f "$RELAY_ENV" ]; then
  echo "  ✓ Relay config found: $RELAY_ENV"
else
  echo "  WebSocket Relay (connects your mesh across the internet)"
  echo ""
  read -p "  Relay URL (e.g. wss://sym-relay.onrender.com, or empty to skip): " RELAY_URL
  if [ -n "$RELAY_URL" ]; then
    read -p "  Relay token (or empty for open access): " RELAY_TOKEN
    echo "SYM_RELAY_URL=$RELAY_URL" > "$RELAY_ENV"
    if [ -n "$RELAY_TOKEN" ]; then
      echo "SYM_RELAY_TOKEN=$RELAY_TOKEN" >> "$RELAY_ENV"
    fi
    echo "  ✓ Relay config saved: $RELAY_ENV"
  else
    echo "  → Skipping relay — using Bonjour (local network) only"
  fi
fi

# ── Step 2: Install sym-daemon ──────────────────────────────

echo ""
echo "  Installing sym-daemon (persistent mesh node)..."

if [ "$(uname)" = "Darwin" ]; then
  # macOS: install as launchd LaunchAgent
  node "$DAEMON_SCRIPT" --install
  echo "  ✓ sym-daemon installed as launchd LaunchAgent"
  echo "    Auto-starts on login, auto-restarts on crash"
  echo "    Logs: ~/Library/Logs/sym-daemon/"
else
  echo "  → macOS not detected. Start the daemon manually:"
  echo "    node $DAEMON_SCRIPT"
  echo "    (On Linux, create a systemd service)"
fi

# ── Step 3: Add MCP server ──────────────────────────────────

echo ""
echo "  Adding SYM MCP server to Claude Code..."
claude mcp add --transport stdio sym --scope user -- node "$MCP_SERVER"
echo "  ✓ MCP server registered"

# ── Step 4: Auto-approve sym_mood ───────────────────────────

echo ""
echo "  Auto-approving sym_mood tool..."
CLAUDE_JSON="$HOME/.claude.json"
if [ -f "$CLAUDE_JSON" ]; then
  node -e "
    const fs = require('fs');
    const config = JSON.parse(fs.readFileSync('$CLAUDE_JSON', 'utf8'));
    if (config.projects) {
      for (const [path, project] of Object.entries(config.projects)) {
        if (!project.allowedTools) project.allowedTools = [];
        if (!project.allowedTools.includes('mcp:sym:sym_mood')) {
          project.allowedTools.push('mcp:sym:sym_mood');
        }
      }
    }
    fs.writeFileSync('$CLAUDE_JSON', JSON.stringify(config, null, 2));
  "
  echo "  ✓ sym_mood auto-approved"
else
  echo "  → No .claude.json found — approve sym_mood manually when prompted"
fi

# ── Step 5: Install CLAUDE.md ───────────────────────────────

echo ""
PROJECT_DIR="${1:-$(pwd)}"
CLAUDE_MD="$PROJECT_DIR/CLAUDE.md"

if [ -f "$CLAUDE_MD" ] && grep -q "SYM Mesh Agent" "$CLAUDE_MD"; then
  echo "  ✓ CLAUDE.md already has SYM instructions"
else
  cat "$SYM_DIR/CLAUDE.md" >> "$CLAUDE_MD"
  echo "  ✓ Added SYM instructions to $CLAUDE_MD"
fi

# ── Done ────────────────────────────────────────────────────

echo ""
echo "  ──────────────────────────────────────"
echo "  SYM is ready."
echo ""
echo "  • sym-daemon: running (check: node $DAEMON_SCRIPT --status)"
echo "  • MCP server: registered (restart Claude Code to activate)"
echo "  • Protocol spec: https://sym.bot/protocol"
echo ""
echo "  Say 'I'm exhausted' in Claude Code —"
echo "  MeloTune plays calming music, MeloMove suggests recovery exercises."
echo ""
