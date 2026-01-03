#!/usr/bin/env bash
# One-command launcher for Git Bash/WSL. Starts backend and frontend together.
set -euo pipefail

root_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$root_dir"

echo "Starting backend (npm start) in $root_dir"
npm start >/tmp/glowup-backend.log 2>&1 &
backend_pid=$!

echo "Starting frontend (npm run dev) in $root_dir/clerk-javascript"
cd "$root_dir/clerk-javascript"
npm run dev >/tmp/glowup-frontend.log 2>&1 &
frontend_pid=$!
cd "$root_dir"

echo "Backend PID: $backend_pid (logs: /tmp/glowup-backend.log)"
echo "Frontend PID: $frontend_pid (logs: /tmp/glowup-frontend.log)"
echo "Frontend will be at http://localhost:5173/ (proxying API to http://localhost:3000)"
echo "Press Ctrl+C to stop both."

trap "echo Stopping...; kill $backend_pid $frontend_pid 2>/dev/null" INT TERM
wait $backend_pid $frontend_pid
