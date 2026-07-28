#!/bin/bash
# ─── Vaultly Setup ──────────────────────────────────────────
# Run: bash vaultly/setup.sh
set -e

echo "🔐 Vaultly Setup"
echo "================"
echo ""

# Step 1: Initialize
echo "Step 1: Create your master password"
echo "  (min 8 chars, encrypts everything locally)"
vaultly init
echo ""

# Step 2: Keychain
echo "Step 2: Store in macOS Keychain for auto-unlock"
vaultly keychain store
echo ""

# Step 3: Cloudflare accounts
echo "Step 3: Add Cloudflare accounts"
echo "  Get tokens from: https://dash.cloudflare.com/profile/api-tokens"
echo "  Add as many as you want. Press Enter with no name to stop."
echo ""

while true; do
  read -p "  Account name (e.g. personal, work, client-x): " name
  [ -z "$name" ] && break
  vaultly cf add "$name"
  echo ""
done

# Step 4: Other credentials
echo "Step 4: Add other credentials (optional)"
echo "  Examples:"
echo "    vaultly template github"
echo "    vaultly add stripe -k STRIPE_SECRET_KEY -v 'sk_live_xxx'"
echo ""
read -p "  Add a GitHub account now? (y/n) " yn
if [ "$yn" = "y" ]; then
  vaultly template github
fi
echo ""

# Step 5: Verify
echo "Step 5: Verify"
vaultly status
echo ""

echo "✅ Setup complete!"
echo ""
echo "Usage:"
echo "  vaultly cf list                          # your CF accounts"
echo "  vaultly cf deploy personal ~/project     # deploy a Worker"
echo "  vaultly run github -- git push           # run with injected creds"
echo ""
echo "Connect your AI tool (MCP config):"
echo '  { "vaultly": { "command": "vaultly", "args": ["mcp"] } }'
echo ""
echo "Then tell your agent: 'deploy my project to Cloudflare'"
