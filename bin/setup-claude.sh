#!/bin/bash
# SYM — Setup for Claude Code
#
# Installs:
#   1. sym-daemon (persistent mesh node, launchd LaunchAgent)
#   2. SYM skill for Claude Code (CAT7 field extraction + CLI interaction)
#
# Usage:
#   sym setup                        # or
#   ./bin/setup-claude.sh [project-dir]

set -e

SYM_DIR="$(cd "$(dirname "$0")/.." && pwd)"
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
  node "$DAEMON_SCRIPT" --install
  echo "  ✓ sym-daemon installed as launchd LaunchAgent"
  echo "    Auto-starts on login, auto-restarts on crash"
  echo "    Logs: ~/Library/Logs/sym-daemon/"
else
  echo "  → macOS not detected. Start the daemon manually:"
  echo "    node $DAEMON_SCRIPT"
  echo "    (On Linux, create a systemd service)"
fi

# ── Step 3: Install SYM skill ────────────────────────────────

echo ""
PROJECT_DIR="${1:-$(pwd)}"
SKILL_SRC="$SYM_DIR/.claude/skills/sym/SKILL.md"
SKILL_DST="$PROJECT_DIR/.claude/skills/sym/SKILL.md"

mkdir -p "$(dirname "$SKILL_DST")"
cp "$SKILL_SRC" "$SKILL_DST"
echo "  ✓ SYM skill installed: $SKILL_DST"

# ── Done ────────────────────────────────────────────────────

echo ""
echo "  ──────────────────────────────────────"
echo "  SYM is ready. Claude Code is on the mesh."
echo ""
echo "  • sym-daemon: running (check: sym status)"
echo "  • SYM skill: installed (Claude Code extracts CAT7 fields and shares observations)"
echo "  • Protocol spec: https://sym.bot/spec/mmp"
echo ""
echo "  The skill teaches Claude Code how to observe, share, and act on the mesh."
echo "  Other agents discover each other automatically via Bonjour."
echo ""
