#!/usr/bin/env python3
"""
Decision Engine for AI-NGFW

Runs in a loop and, every ~30 seconds per active flow:

- Reads sessions from sessions.db (table: sessions)
- For each non-closed flow (unless locked by ids_override):
    * Calls anomaly model:
        GET http://localhost:5001/predict/<flow_key>
        -> { "label": 0/1, "prob_attack": float, "session_id": "..." }

    * Computes simple Threat Intel score from ti_metadata table

    * Computes endpoint agent score by pinging http://<internal_ip>:8080/

    * Generates IAM score randomly for now.

    * Merges scores into combined_score.

    * Updates sessions table:
        - anomaly_score, ti_score, endpoint_score, iam_score, combined_score
        - decision_action ("allow"/"block")
        - decision_label, decision_score, decision_tier, decision_reason
        - last_decision_ts (timestamp)

- If combined_score exceeds threshold and decision_action == "block":
    * Calls SOAR /block API:
        POST http://localhost:6003/block { "ip": "<chosen_ip>" }

NEW IMPORTANT BEHAVIOR:
- If a session already has decision_tier = 'ids_override' AND decision_action = 'block',
  this engine will SKIP that flow completely (manual override is treated as locked).
"""

import sqlite3
import time
import random
import requests
import ipaddress
import json
import re
from pathlib import Path
from typing import Optional, Tuple, List

DB_FILE = "sessions.db"

ANOMALY_URL_TEMPLATE = "http://localhost:5001/predict/{flow_key}"
SOAR_BLOCK_URL = "http://localhost:6003/block"
DECISION_INTERVAL = 30.0

BLOCK_THRESHOLD = 0.8

W_ANOMALY = 0.4
W_TI = 0.3
W_ENDPOINT = 0.2
W_IAM = 0.1


# ─────────────────────────────────────────────
#  DB helpers
# ─────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    db_path = Path(DB_FILE)
    if not db_path.exists():
        raise SystemExit(f"[DECISION] Database file {DB_FILE} not found. Run forwarder first.")
    conn = sqlite3.connect(DB_FILE, timeout=15.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=8000")
    return conn


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cur.fetchall()]
    return column in cols


def ensure_extra_columns(conn: sqlite3.Connection):
    """
    Add decision-engine-specific columns to sessions IF they don't exist.
    """
    cur = conn.cursor()

    extra_cols = {
        "decision_action": "TEXT",
        "decision_label": "TEXT",
        "decision_score": "REAL",
        "decision_tier": "TEXT",
        "decision_reason": "TEXT",
        "anomaly_score": "REAL",
        "ti_score": "REAL",
        "endpoint_score": "REAL",
        "iam_score": "REAL",
        "combined_score": "REAL",
        "risk_score": "REAL",
        "score_updated_ts": "REAL",
        "last_decision_ts": "REAL",
    }

    for col, ctype in extra_cols.items():
        if not column_exists(conn, "sessions", col):
            print(f"[DECISION] Adding column sessions.{col} ({ctype})")
            cur.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ctype}")

    conn.commit()


def fetch_active_sessions(conn: sqlite3.Connection):
    """
    Return all non-closed sessions.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE state NOT LIKE 'CLOSED%'
           OR state IS NULL
        """
    )
    return cur.fetchall()


def fetch_ti_for_flow(conn: sqlite3.Connection, flow_key: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM ti_metadata WHERE flow_key = ?", (flow_key,))
        return cur.fetchone()
    except sqlite3.OperationalError:
        return None


def update_session_decision(
    conn: sqlite3.Connection,
    flow_key: str,
    anomaly_score: float,
    ti_score: float,
    endpoint_score: float,
    iam_score: float,
    combined_score: float,
    decision_action: str,
    decision_label: str,
    decision_tier: str,
    decision_reason: str,
    now_ts: float,
):
    def _do_update() -> None:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE sessions
            SET
                anomaly_score   = ?,
                ti_score        = ?,
                endpoint_score  = ?,
                iam_score       = ?,
                combined_score  = ?,
                risk_score      = ?,
                score_updated_ts = ?,
                decision_action = ?,
                decision_label  = ?,
                decision_score  = ?,
                decision_tier   = ?,
                decision_reason = ?,
                last_decision_ts = ?
            WHERE flow_key = ?
            """,
            (
                anomaly_score,
                ti_score,
                endpoint_score,
                iam_score,
                combined_score,
                combined_score,
                now_ts,
                decision_action,
                decision_label,
                combined_score,
                decision_tier,
                decision_reason,
                now_ts,
                flow_key,
            ),
        )
        conn.commit()

    try:
        _do_update()
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "no such column" in message:
            ensure_extra_columns(conn)
            _do_update()
        else:
            raise
    print(
        f"[DECISION] Updated {flow_key}: action={decision_action}, "
        f"score={combined_score:.3f}, reason={decision_reason}"
    )


# ─────────────────────────────────────────────
#  Scoring helpers
# ─────────────────────────────────────────────

def call_anomaly(flow_key: str) -> Tuple[float, str]:
    url = ANOMALY_URL_TEMPLATE.format(flow_key=flow_key)
    try:
        r = requests.get(url, timeout=0.5)
        if r.status_code != 200:
            return 0.0, f"anomaly_http_{r.status_code}"
        data = r.json()
        prob_attack = float(data.get("prob_attack", 0.0))
        label = data.get("label", 0)
        return prob_attack, f"anomaly_label={label}"
    except Exception as e:
        return 0.0, f"anomaly_error:{e.__class__.__name__}"


def compute_ti_score(ti_row: Optional[sqlite3.Row]) -> Tuple[float, str]:
    if ti_row is None:
        return 0.0, "ti_none"

    keys = ti_row.keys()
    http_host = ti_row["http_host"] if "http_host" in keys else None
    url = ti_row["url"] if "url" in keys else None
    tls_sni = ti_row["tls_sni"] if "tls_sni" in keys else None
    tls_ja3 = ti_row["tls_ja3"] if "tls_ja3" in keys else None

    score = 0.0
    reasons = []
    if http_host:
        score += 0.20
        reasons.append("host")
    if url:
        score += 0.20
        reasons.append("url")
    if tls_sni:
        score += 0.15
        reasons.append("sni")
    if tls_ja3:
        score += 0.10
        reasons.append("ja3")

    suspicious_markers = ("login", "admin", "token", "exe", "powershell", "cmd", "download")
    blob = f"{http_host or ''} {url or ''} {tls_sni or ''}".lower()
    if any(marker in blob for marker in suspicious_markers):
        score += 0.20
        reasons.append("pattern")

    score = min(score, 1.0)
    reason = "ti_" + ",".join(reasons) if reasons else "ti_metadata_empty"
    return score, reason


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def choose_endpoint_candidates(ip_src: str, ip_dst: str) -> List[str]:
    src_private = is_private_ip(ip_src)
    dst_private = is_private_ip(ip_dst)

    candidates: List[str] = []

    if src_private and not dst_private:
        candidates.append(ip_src)
    elif not src_private and dst_private:
        candidates.append(ip_dst)
    elif src_private and dst_private:
        candidates.extend([ip_src, ip_dst])
    else:
        candidates.extend([ip_src, ip_dst])

    if ip_src not in candidates:
        candidates.append(ip_src)
    if ip_dst not in candidates:
        candidates.append(ip_dst)

    filtered = []
    for candidate in candidates:
        if candidate and candidate not in filtered:
            filtered.append(candidate)
    return filtered


def parse_endpoint_score_response(body_text: str, content_type: str) -> Optional[float]:
    text = (body_text or "").strip()
    ctype = (content_type or "").lower()

    if "application/json" in ctype or (text.startswith("{") and text.endswith("}")):
        try:
            payload = json.loads(text)
            for key in ("score", "risk", "risk_score", "endpoint_score", "value", "prob_attack"):
                if key in payload:
                    value = float(payload[key])
                    return value / 100.0 if value > 1.0 else value
        except Exception:
            pass

    try:
        raw = float(text)
        return raw / 100.0 if raw > 1.0 else raw
    except Exception:
        pass

    match = re.search(r"(-?\d+(?:\.\d+)?)", text)
    if match:
        try:
            raw = float(match.group(1))
            return raw / 100.0 if raw > 1.0 else raw
        except Exception:
            return None

    return None


def compute_endpoint_score(ip_src: str, ip_dst: str) -> Tuple[float, str]:
    candidates = choose_endpoint_candidates(ip_src, ip_dst)
    if not candidates:
        return 0.5, "endpoint_no_candidates"

    last_reason = "endpoint_no_response"
    for candidate in candidates:
        url = f"http://{candidate}:8080/"
        try:
            response = requests.get(url, timeout=0.6)
            if response.status_code != 200:
                last_reason = f"endpoint_http_{response.status_code}:{candidate}"
                continue

            parsed = parse_endpoint_score_response(
                response.text,
                response.headers.get("Content-Type", "")
            )
            if parsed is None:
                last_reason = f"endpoint_parse_failed:{candidate}"
                continue

            score = max(0.0, min(parsed, 1.0))
            return score, f"endpoint_ok:{candidate}"
        except Exception as exc:
            last_reason = f"endpoint_unreachable:{candidate}:{exc.__class__.__name__}"

    return 0.5, last_reason


def compute_iam_score() -> Tuple[float, str]:
    score = random.uniform(0.2, 0.6)
    return score, "iam_random"


def merge_scores(
    anomaly_score: float,
    ti_score: float,
    endpoint_score: float,
    iam_score: float,
) -> float:
    combined = (
        W_ANOMALY * anomaly_score +
        W_TI * ti_score +
        W_ENDPOINT * endpoint_score +
        W_IAM * iam_score
    )
    return max(0.0, min(combined, 1.0))


def decide_action(combined_score: float) -> str:
    if combined_score >= BLOCK_THRESHOLD:
        return "block"
    return "allow"


def build_reason(
    anomaly_info: str,
    ti_info: str,
    endpoint_info: str,
    iam_info: str,
    combined_score: float,
) -> str:
    return (
        f"combined={combined_score:.3f}; "
        f"{anomaly_info}; {ti_info}; {endpoint_info}; {iam_info}"
    )


# ─────────────────────────────────────────────
#  SOAR integration
# ─────────────────────────────────────────────

def call_soar_block(ip: str) -> Tuple[bool, str]:
    try:
        payload = {"ip": ip}
        r = requests.post(SOAR_BLOCK_URL, json=payload, timeout=1.0)
        if r.status_code != 200:
            return False, f"soar_http_{r.status_code}"
        data = r.json()
        return True, f"soar_block_ok_ticket={data.get('ticket_id', '?')}"
    except Exception as e:
        return False, f"soar_error:{e.__class__.__name__}"


def choose_ip_for_soar(ip_src: str, ip_dst: str) -> str:
    candidates = choose_endpoint_candidates(ip_src, ip_dst)
    ip = candidates[0] if candidates else None
    return ip or ip_src or ip_dst


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def main_loop():
    conn = get_conn()
    ensure_extra_columns(conn)

    print("[DECISION] Decision engine started. Scanning flows every few seconds...")

    while True:
        now_ts = time.time()
        sessions = fetch_active_sessions(conn)

        for row in sessions:
            flow_key = row["flow_key"]
            state = row["state"] or ""
            ip_src = row["ip_src"]
            ip_dst = row["ip_dst"]

            # Skip closed sessions
            if state.startswith("CLOSED"):
                continue

            # 🔒 IMPORTANT: respect manual IDS override blocks
            existing_tier = row["decision_tier"] if "decision_tier" in row.keys() else None
            existing_action = row["decision_action"] if "decision_action" in row.keys() else None
            if existing_tier == "ids_override" and existing_action == "block":
                print(f"[DECISION] Skipping {flow_key}, locked by ids_override")
                continue

            last_dec_ts = row["last_decision_ts"] if "last_decision_ts" in row.keys() else None
            if last_dec_ts is not None and (now_ts - last_dec_ts) < DECISION_INTERVAL:
                continue

            print(f"[DECISION] Evaluating flow {flow_key}")

            anomaly_score, anomaly_info = call_anomaly(flow_key)

            ti_row = fetch_ti_for_flow(conn, flow_key)
            ti_score, ti_info = compute_ti_score(ti_row)

            endpoint_score, endpoint_info = compute_endpoint_score(ip_src, ip_dst)

            iam_score, iam_info = compute_iam_score()

            combined_score = merge_scores(
                anomaly_score,
                ti_score,
                endpoint_score,
                iam_score,
            )

            action = decide_action(combined_score)
            label = "decision_engine"
            tier = "decision_engine"

            reason = build_reason(
                anomaly_info,
                ti_info,
                endpoint_info,
                iam_info,
                combined_score,
            )

            update_session_decision(
                conn,
                flow_key,
                anomaly_score,
                ti_score,
                endpoint_score,
                iam_score,
                combined_score,
                action,
                label,
                tier,
                reason,
                now_ts,
            )

            if action == "block":
                ip_for_soar = choose_ip_for_soar(ip_src, ip_dst)
                if ip_for_soar:
                    ok, soar_info = call_soar_block(ip_for_soar)
                    print(
                        f"[DECISION] SOAR block for {ip_for_soar} "
                        f"from flow {flow_key}: {soar_info}"
                    )

        time.sleep(5.0)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[DECISION] Stopped by user.")
