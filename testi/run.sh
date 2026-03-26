#!/usr/bin/env bash

set -euo pipefail

INSTANCE_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$INSTANCE_DIR")"
VENV_DIR="$BASE_DIR/venv"
VENV_PY="$VENV_DIR/bin/python3"
STREAMLIT_BIN="$VENV_DIR/bin/streamlit"
LOG_DIR="$INSTANCE_DIR/logs"
PID_FILE="$INSTANCE_DIR/.testi_pids"

mkdir -p "$LOG_DIR"

echo "[+] Starting NGFW stack (testi only)"
echo "[+] Instance dir: $INSTANCE_DIR"

echo "[*] Pre-cleaning any existing testi services"
"$INSTANCE_DIR/stop.sh" || true

: > "$PID_FILE"

auto_pid_file() {
    local name="$1"
    case "$name" in
        anomaly) echo "$INSTANCE_DIR/.anomaly.pid" ;;
        fastclass) echo "$INSTANCE_DIR/.fastclass.pid" ;;
        decision) echo "$INSTANCE_DIR/.decision.pid" ;;
        soar) echo "$INSTANCE_DIR/.soar_api.pid" ;;
        forwarder) echo "$INSTANCE_DIR/.forwarder.pid" ;;
        tap23layer4) echo "$INSTANCE_DIR/.tap_layer4.pid" ;;
        dashboard) echo "$INSTANCE_DIR/.dashboard.pid" ;;
        *) echo "$INSTANCE_DIR/.${name}.pid" ;;
    esac
}

record_pid() {
    local pid="$1"
    local name="$2"
    local pid_path
    pid_path="$(auto_pid_file "$name")"
    printf "%s|%s|%s\n" "$pid" "$name" "$INSTANCE_DIR" >> "$PID_FILE"
    echo "$pid" > "$pid_path"
}

if [ ! -x "$VENV_PY" ]; then
    echo "[-] Python executable not found at $VENV_PY"
    exit 1
fi

export PYTHONPATH="$INSTANCE_DIR:${PYTHONPATH:-}"

start_python() {
    local script="$1"
    local name="$2"
    local need_sudo="$3"
    local log="$LOG_DIR/${name}.log"

    if [ ! -f "$INSTANCE_DIR/$script" ]; then
        return
    fi

    echo "[+] Starting $name"
    if [ "$need_sudo" = "yes" ]; then
        (
            cd "$INSTANCE_DIR"
            exec setsid sudo "$VENV_PY" "$script" >> "$log" 2>&1
        ) &
    else
        (
            cd "$INSTANCE_DIR"
            exec setsid "$VENV_PY" "$script" >> "$log" 2>&1
        ) &
    fi

    local pid=$!
    record_pid "$pid" "$name"
    sleep 1
}

start_dashboard() {
    local app_py="dashboard_app.py"
    local name="dashboard"
    local log="$LOG_DIR/${name}.log"

    if [ ! -f "$INSTANCE_DIR/$app_py" ]; then
        return
    fi

    if [ ! -x "$STREAMLIT_BIN" ]; then
        echo "[-] Streamlit executable not found at $STREAMLIT_BIN"
        exit 1
    fi

    echo "[+] Starting $name"
    (
        cd "$INSTANCE_DIR"
        exec setsid "$STREAMLIT_BIN" run "$app_py" >> "$log" 2>&1
    ) &

    local pid=$!
    record_pid "$pid" "$name"
    sleep 1
}

if [ -f "$INSTANCE_DIR/taps.sh" ]; then
    echo "[*] Running TAP setup for testi"
    sudo bash "$INSTANCE_DIR/taps.sh" || true
fi

start_python "anomaly.py" "anomaly" "no"
start_python "fastclass.py" "fastclass" "no"
start_python "decision4.py" "decision" "no"
start_python "soar_api.py" "soar" "no"
start_python "forwarder.py" "forwarder" "yes"
start_python "tap23layer4.py" "tap23layer4" "yes"
start_dashboard

echo "[✓] Testi startup complete"
echo "[i] PID index: $PID_FILE"
echo "[i] Logs: $LOG_DIR"
echo "[i] Use ./stop.sh to stop testi services"
