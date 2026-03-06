#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/Backend_Go"
GUI_DIR="$SCRIPT_DIR/GUI"
VENV_ACTIVATE="$SCRIPT_DIR/venv/bin/activate"
SERVER_BIN="$SCRIPT_DIR/.va-server"

cleanup() {
    echo ""
    echo "Stopping backend (PID $BACKEND_PID)..."
    kill "$BACKEND_PID" 2>/dev/null
    wait "$BACKEND_PID" 2>/dev/null
    rm -f "$SERVER_BIN"
    echo "Done."
}
trap cleanup EXIT

# 1. Build Go binary
echo "[1/3] Building backend..."
(cd "$BACKEND_DIR" && go build -o "$SERVER_BIN" ./cmd/scanner) || {
    echo "Build failed. Exiting."
    exit 1
}

# 2. Start backend in background
echo "[2/3] Starting backend..."
"$SERVER_BIN" &
BACKEND_PID=$!

# 3. Wait for backend to be ready (max 10s)
echo "[3/3] Waiting for backend..."
READY=0
for i in $(seq 1 10); do
    if curl -sf http://127.0.0.1:5500/health > /dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -eq 0 ]; then
    echo "Backend did not start in time. Check for errors above."
    exit 1
fi
echo "Backend ready on http://127.0.0.1:5500"

# 4. Activate venv and start GUI (foreground)
source "$VENV_ACTIVATE"
cd "$GUI_DIR"
python main.py
