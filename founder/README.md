# Sentinel-9 — founder scripts

One-command control for the Cyber Citadel AI app (the `ironhorse6911` repo),
so you don't have to remember the startup steps.

## Scripts

- `bash founder/startup.sh` — starts the dev server in the background.
  Checks that `.env` exists, installs dependencies if `node_modules` is
  missing, then prints the Local URL when Vite is ready. Logs go to
  `founder/logs/dev.log`.
- `bash founder/shutdown.sh` — stops the dev server.
- `bash founder/repair.sh` — pulls the latest code, reinstalls dependencies,
  checks `.env`, and restarts the dev server.

## What it needs

- A local `.env` in the repo root with:
  - `VITE_SUPABASE_URL=https://<project-id>.supabase.co`
  - `VITE_SUPABASE_PUBLISHABLE_KEY=<new publishable key>`
- `.env` is gitignored and must never be committed. The old committed `.env`
  was stripped from git history on Nov 9, 2026 and the Supabase keys were
  rotated the same day.

## Notes

- The dev port is auto-detected by the Lovable Vite config — it was
  `localhost:8080` on Nov 9, 2026, but `startup.sh` prints the real URL from
  the log each time, so just read what it says.
- `startup.sh` won't start a second server if one is already running.
- Run scripts with `bash founder/...` — no chmod needed after pulling.
