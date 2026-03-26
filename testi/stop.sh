#!/usr/bin/env bash

set -euo pipefail

INSTANCE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$INSTANCE_DIR/.testi_pids"
PID_FILES=(
    "$INSTANCE_DIR/.anomaly.pid"
    "$INSTANCE_DIR/.fastclass.pid"
    "$INSTANCE_DIR/.decision.pid"
    "$INSTANCE_DIR/.soar_api.pid"
    "$INSTANCE_DIR/.forwarder.pid"
    "$INSTANCE_DIR/.tap_layer4.pid"
    "$INSTANCE_DIR/.dashboard.pid"
)

echo "[+] Stopping NGFW stack (testi only)"
echo "[+] Instance dir: $INSTANCE_DIR"

stopped_any=0

SUDO_CMD=""
if [ "${EUID}" -ne 0 ]; then
    SUDO_CMD="sudo"
    echo "[*] stop.sh needs sudo privileges to stop root-owned services"
    "$SUDO_CMD" -v
fi

pid_file_for_name() {
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

stop_pid() {
    local pid="$1"
    local label="$2"

    if [ -z "${pid:-}" ] || ! [[ "$pid" =~ ^[0-9]+$ ]]; then
        return
    fi

    local pgid="-$pid"

    if ! ps -p "$pid" > /dev/null 2>&1; then
        echo "[i] $label is already stopped (PID: $pid)"
    else
        echo "[+] Stopping $label (PID: $pid)"
        stopped_any=1
        kill "$pid" 2>/dev/null || true
        kill "$pgid" 2>/dev/null || true
        sleep 1

        if ps -p "$pid" > /dev/null 2>&1; then
            if [ -n "$SUDO_CMD" ]; then
                "$SUDO_CMD" kill "$pid" 2>/dev/null || true
                "$SUDO_CMD" kill "$pgid" 2>/dev/null || true
            fi
            sleep 1
        fi

        if ps -p "$pid" > /dev/null 2>&1; then
            echo "[*] Force killing $label (PID: $pid)"
            kill -9 "$pid" 2>/dev/null || true
            kill -9 "$pgid" 2>/dev/null || true
            sleep 1
        fi

        if ps -p "$pid" > /dev/null 2>&1; then
            if [ -n "$SUDO_CMD" ]; then
                "$SUDO_CMD" kill -9 "$pid" 2>/dev/null || true
                "$SUDO_CMD" kill -9 "$pgid" 2>/dev/null || true
            fi
        fi
    fi
}

cleanup_by_signature() {
    local patterns=(
        "/home/ketan/neurawall/venv/bin/python3 anomaly.py"
        "/home/ketan/neurawall/venv/bin/python3 fastclass.py"
        "/home/ketan/neurawall/venv/bin/python3 decision4.py"
        "/home/ketan/neurawall/venv/bin/python3 soar_api.py"
        "/home/ketan/neurawall/venv/bin/python3 forwarder.py"
        "/home/ketan/neurawall/venv/bin/python3 tap23layer4.py"
        "/home/ketan/neurawall/venv/bin/streamlit run dashboard_app.py"
    )

    echo "[*] PID records missing/stale; running signature cleanup"
    for pattern in "${patterns[@]}"; do
        while read -r pid; do
            if [ -z "${pid:-}" ] || [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ]; then
                continue
            fi
            stop_pid "$pid" "signature:$pattern"
        done < <(pgrep -f "$pattern" 2>/dev/null || true)
    done
}

if [ -f "$PID_FILE" ]; then
    while IFS='|' read -r pid name cwd; do
        if [ -z "${pid:-}" ] || [ -z "${name:-}" ]; then
            continue
        fi
        stop_pid "$pid" "$name"
        rm -f "$(pid_file_for_name "$name")"
    done < "$PID_FILE"

    rm -f "$PID_FILE"
else
    echo "[i] PID index not found at $PID_FILE"
fi

for pid_path in "${PID_FILES[@]}"; do
    if [ -f "$pid_path" ]; then
        pid="$(cat "$pid_path" 2>/dev/null || true)"
        stop_pid "$pid" "pidfile:$(basename "$pid_path")"
    fi
done

if [ "$stopped_any" -eq 0 ]; then
    cleanup_by_signature
fi

rm -f "$PID_FILE" "${PID_FILES[@]}"

echo "[✓] Testi services stopped"
echo "[i] Use ./run.sh to start testi services"
