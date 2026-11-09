#!/usr/bin/env bash
# Sentinel-9 repair — pulls the latest code, reinstalls deps, checks .env,
# and restarts the dev server. Run from anywhere: bash founder/repair.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Pulling latest code..."
git stash push -m "repair-stash" --include-untracked || true
git pull
git stash pop || true

echo "Installing dependencies..."
pnpm install

if [ ! -f "$ROOT/.env" ]; then
  echo "Warning: .env is missing — the app needs VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY."
else
  echo ".env found."
fi

echo "Restarting dev server..."
bash "$ROOT/founder/shutdown.sh" || true
bash "$ROOT/founder/startup.sh"
