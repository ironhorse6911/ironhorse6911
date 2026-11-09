#!/usr/bin/env bash
# Sentinel-9 shutdown — stops the dev server started by founder/startup.sh.
# Run from anywhere: bash founder/shutdown.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/founder/logs"

if [ -f "$LOG_DIR/dev.pid" ]; then
  PID="$(cat "$LOG_DIR/dev.pid")"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "Stopped Sentinel-9 dev server (PID $PID)."
  else
    echo "Dev server (PID $PID) was already stopped."
  fi
  rm -f "$LOG_DIR/dev.pid"
else
  echo "No PID file found — trying to stop any running 'vite dev' for this folder..."
  pkill -f "vite dev" || echo "No dev server was running."
fi
