#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$BASE_DIR/venv"
VENV_PY="$VENV_DIR/bin/python3"
PID_FILE="$BASE_DIR/.ngfw_pids"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"
: > "$PID_FILE"

echo "[+] Starting NGFW stack (all available instance services)"
echo "[+] Base dir: $BASE_DIR"

if [ ! -x "$VENV_PY" ]; then
    echo "[-] Python executable not found at $VENV_PY"
    exit 1
fi

record_pid() {
    local pid="$1"
    local name="$2"
    local cwd="$3"
    printf "%s|%s|%s\n" "$pid" "$name" "$cwd" >> "$PID_FILE"
}

start_python() {
    local cwd="$1"
    local script="$2"
    local label="$3"
    local need_sudo="$4"
    local log="$LOG_DIR/${label}.log"

    if [ ! -f "$cwd/$script" ]; then
        return
    fi

    echo "[+] Starting $label"
    if [ "$need_sudo" = "yes" ]; then
        (
            cd "$cwd"
            sudo "$VENV_PY" "$script" >> "$log" 2>&1
        ) &
    else
        (
            cd "$cwd"
            "$VENV_PY" "$script" >> "$log" 2>&1
        ) &
    fi

    local pid=$!
    record_pid "$pid" "$label" "$cwd"
    sleep 1
}

start_streamlit() {
    local cwd="$1"
    local app_py="$2"
    local label="$3"
    local log="$LOG_DIR/${label}.log"

    if [ ! -f "$cwd/$app_py" ]; then
        return
    fi

    echo "[+] Starting $label"
    (
        cd "$cwd"
        "$VENV_DIR/bin/streamlit" run "$app_py" >> "$log" 2>&1
    ) &
    local pid=$!
    record_pid "$pid" "$label" "$cwd"
    sleep 1
}

if [ -f "$BASE_DIR/taps.sh" ]; then
    echo "[*] Running TAP setup"
    sudo bash "$BASE_DIR/taps.sh" || true
fi

for inst in instance1 instance2; do
    inst_dir="$BASE_DIR/$inst"
    if [ ! -d "$inst_dir" ]; then
        continue
    fi

    echo "[+] Booting $inst"
    start_python "$inst_dir" "anomaly.py" "${inst}_anomaly" "no"
    start_python "$inst_dir" "fastclass.py" "${inst}_fastclass" "no"
    start_python "$inst_dir" "decision4.py" "${inst}_decision" "no"
    start_python "$inst_dir" "soar_api.py" "${inst}_soar" "no"
    start_python "$inst_dir" "forwarder.py" "${inst}_forwarder" "yes"
    start_streamlit "$inst_dir" "dashboard_app.py" "${inst}_dashboard"
done

echo "[✓] Startup complete"
echo "[i] PID file: $PID_FILE"
echo "[i] Logs: $LOG_DIR"
