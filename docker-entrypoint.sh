#!/bin/sh
# security-forge — one image, two modes.
#   first arg `ui` / `web` / `serve`  -> launch the web UI (uvicorn)
#   anything else                     -> pass through to the CLI orchestrator
set -e

# Ensure the persistent dirs exist (agent-CLI logins live under $HOME on /data).
mkdir -p "${HOME:-/data/home}" "${SECFORGE_DATA_DIR:-/data}" 2>/dev/null || true

case "${1:-}" in
  ui|web|serve)
    shift
    exec uvicorn app:app --app-dir /app/webapp --host 0.0.0.0 --port "${PORT:-8000}" "$@"
    ;;
  *)
    exec python orchestrate.py "$@"
    ;;
esac
