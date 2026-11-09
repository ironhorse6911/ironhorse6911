#!/usr/bin/env bash
# Sentinel-9 startup — starts the Cyber Citadel AI dev server.
# Run from anywhere: bash founder/startup.sh
# Logs: founder/logs/dev.log | PID: founder/logs/dev.pid
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/founder/logs"
mkdir -p "$LOG_DIR"

cd "$ROOT"

# Keys must exist locally; they are never committed (.env is gitignored).
if [ ! -f "$ROOT/.env" ]; then
  echo "Missing .env in $ROOT — create it with your Supabase keys first:"
  echo "  VITE_SUPABASE_URL=https://<project-id>.supabase.co"
  echo "  VITE_SUPABASE_PUBLISHABLE_KEY=<new publishable key>"
  exit 1
fi
for var in VITE_SUPABASE_URL VITE_SUPABASE_PUBLISHABLE_KEY; do
  if ! grep -q "^$var=" "$ROOT/.env"; then
    echo "Warning: $var is missing from .env — the app may not connect to Supabase."
  fi
done

# Install deps if node_modules is missing.
if [ ! -d "$ROOT/node_modules" ]; then
  echo "Installing dependencies (pnpm install)..."
  pnpm install
fi

# If it's already running, don't start a second one.
if [ -f "$LOG_DIR/dev.pid" ] && kill -0 "$(cat "$LOG_DIR/dev.pid")" 2>/dev/null; then
  echo "Sentinel-9 is already running (PID $(cat "$LOG_DIR/dev.pid"))."
  grep -m1 "Local:" "$LOG_DIR/dev.log" 2>/dev/null || true
  exit 0
fi

echo "Starting Sentinel-9 dev server..."
nohup pnpm run dev > "$LOG_DIR/dev.log" 2>&1 &
echo $! > "$LOG_DIR/dev.pid"

# Wait for Vite to print its Local URL (port is auto-detected by the Lovable config).
for _ in $(seq 1 30); do
  if grep -q "Local:" "$LOG_DIR/dev.log" 2>/dev/null; then
    break
  fi
  sleep 1
done

grep -m1 "Local:" "$LOG_DIR/dev.log" || echo "Still starting — watch the log: tail -f $LOG_DIR/dev.log"
echo "Logs: $LOG_DIR/dev.log"
