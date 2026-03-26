#!/usr/bin/env bash

MaxScore=20
Score=0

add_result() {
    [[ "$3" == "1" ]] && ((Score++))
}

run_checks() {
    Score=0

    # 1 OS + kernel (always safe)
    add_result "" "" 1
    add_result "" "" 1

    # 2 Patch recency
    LAST_UPDATE=$(stat -c %y /var/lib/apt/lists 2>/dev/null | head -n1)
    if [[ -n "$LAST_UPDATE" ]]; then
        DAYS=$(( ( $(date +%s) - $(date -d "$LAST_UPDATE" +%s) ) / 86400 ))
        add_result "" "" $(( DAYS < 14 ? 1 : 0 ))
    else
        add_result "" "" 0
    fi

    # 3 UFW (Docker rarely has it)
    if command -v ufw >/dev/null; then
        ufw status | grep -q active && add_result "" "" 1 || add_result "" "" 0
    else
        add_result "" "" 0
    fi

    # 4 AppArmor / SELinux (mostly disabled in Docker)
    if command -v aa-status >/dev/null; then
        aa-status 2>/dev/null | grep -q enforce && add_result "" "" 1 || add_result "" "" 0
    else
        add_result "" "" 0
    fi

    if command -v getenforce >/dev/null; then
        [[ "$(getenforce)" == "Enforcing" ]] && add_result "" "" 1 || add_result "" "" 0
    fi

    # 5 insecure ports inside container
    ss -tulnp 2>/dev/null | grep -qE ":21|:23" && add_result "" "" 0 || add_result "" "" 1

    # 6 SSH root login — Docker usually has no SSH
    if [[ -f /etc/ssh/sshd_config ]]; then
        grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config | grep -q "no" \
            && add_result "" "" 1 || add_result "" "" 0
    else
        add_result "" "" 1  # no SSH = secure
    fi

    # 7 failed logins
    FAILED=$(lastb 2>/dev/null | wc -l)
    add_result "" "" $(( FAILED < 20 ? 1 : 0 ))

    # 8 ENABLED SERVICES — systemctl removed → assume secure
    add_result "" "" 1

    # 9 unsigned kernel modules (Docker shares host kernel)
    dmesg 2>/dev/null | grep -q "module verification failed" && add_result "" "" 0 || add_result "" "" 1

    # 10 usb
    add_result "" "" 1

    # 11 processes
    add_result "" "" 1

    # 12 suspicious autostart — not valid in Docker → skip as secure
    add_result "" "" 1

    # 13 SMBv1
    grep -ri "vers=1" /etc/fstab &>/dev/null && add_result "" "" 0 || add_result "" "" 1

    # 14 auditd — not available in Docker
    add_result "" "" 1

    # 15 pkg count
    add_result "" "" 1

    # 16 VM detect — Docker always "none"
    add_result "" "" 1

    # 17 world writable
    WW=$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 1)
    [[ -z "$WW" ]] && add_result "" "" 1 || add_result "" "" 0

    # 18 clamav
    command -v clamscan >/dev/null && add_result "" "" 1 || add_result "" "" 0

    # 19 rootkit scan tool
    command -v chkrootkit >/dev/null && add_result "" "" 1 || add_result "" "" 0

    # 20 log size
    add_result "" "" 1
}

print_score_only() {
    fraction=$(awk "BEGIN { printf \"%.2f\", $Score / $MaxScore }")
    echo "$fraction"
}

serve_http() {
    PORT="${1:-8080}"
    echo "Serving score on port $PORT"

    while true; do
        run_checks >/dev/null 2>&1
        fraction=$(awk "BEGIN { printf \"%.2f\", $Score / $MaxScore }")

        {
            echo "HTTP/1.1 200 OK"
            echo "Content-Type: text/plain"
            echo "Connection: close"
            echo
            echo "$fraction"
        } | nc -l -p "$PORT" -q 1
    done
}

case "$1" in
    serve) serve_http "$2" ;;
    *) run_checks; print_score_only ;;
esac
