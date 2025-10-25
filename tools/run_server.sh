#!/usr/bin/env bash
# Simple helper to start/stop the example server with predictable layout.
# Usage:
#   ./tools/run_server.sh start
#   ./tools/run_server.sh stop
#   ./tools/run_server.sh status

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/bin/server"
LOG_DIR="$ROOT_DIR/logs"
PIDFILE="$ROOT_DIR/logs/server.pid"

mkdir -p "$LOG_DIR"

start() {
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Server already running (PID $(cat "$PIDFILE"))."; exit 0
  fi
  if [ ! -x "$BIN" ]; then
    echo "Binary $BIN not found or not executable. Build first: make"; exit 1
  fi
  # Ensure certs dir is used by server (default is 'certs')
  nohup "$BIN" > "$LOG_DIR/server.out" 2>&1 &
  echo $! > "$PIDFILE"
  echo "Started server (PID $(cat $PIDFILE)). Logs: $LOG_DIR/server.out"
}

stop() {
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" || true
    rm -f "$PIDFILE"
    echo "Stopped server."
  else
    echo "No PID file; server not running?"
  fi
}

status() {
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Server running (PID $(cat "$PIDFILE"))."
  else
    echo "Server not running."
  fi
}

case ${1:-} in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "Usage: $0 {start|stop|status}"; exit 2 ;;
esac
