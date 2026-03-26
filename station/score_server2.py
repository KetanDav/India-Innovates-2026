#!/usr/bin/env python3
import os
import time
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============= CONFIG =============
INTERVAL = 60
HOST = "0.0.0.0"
PORT = 8080

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(BASE_DIR, "endpointfff.sh")

SCORE_FILE = "/tmp/endpoint_score_debug.txt"

# Global latest score
latest_score = "0.00"
lock = threading.Lock()


# ===================================
# EXECUTE endpointfff.sh WITH DEBUG
# ===================================
def compute_score_once():
    global latest_score

    print("\n==============================", flush=True)
    print("[DEBUG] Starting score calculation...", flush=True)
    print("[DEBUG] SCRIPT_PATH =", SCRIPT_PATH, flush=True)

    # Check script exists
    if not os.path.exists(SCRIPT_PATH):
        print("[ERROR] endpointfff.sh NOT FOUND!", flush=True)
        latest_score = "0.00"
        return

    # Check script executable
    if not os.access(SCRIPT_PATH, os.X_OK):
        print("[ERROR] endpointfff.sh is NOT EXECUTABLE!", flush=True)
        print("[FIX] Run: chmod +x endpointfff.sh", flush=True)
        latest_score = "0.00"
        return

    try:
        # Run script
        proc = subprocess.run(
            [SCRIPT_PATH],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        print("[DEBUG] exit code:", proc.returncode, flush=True)
        print("[DEBUG] stdout:", repr(proc.stdout), flush=True)
        print("[DEBUG] stderr:", repr(proc.stderr), flush=True)

        if proc.returncode != 0:
            raise RuntimeError("Script exited with non-zero status")

        # Parse first line
        lines = proc.stdout.strip().splitlines()
        if len(lines) == 0:
            raise ValueError("No output returned from script")

        raw = lines[0].strip()
        print("[DEBUG] raw line =", repr(raw), flush=True)

        value = float(raw)

        # Clamp
        value = max(0.0, min(1.0, value))
        score_str = f"{value:.2f}"

        print("[DEBUG] Parsed score =", score_str, flush=True)

    except Exception as e:
        print("[EXCEPTION]", repr(e), flush=True)
        print("[DEBUG] Using fallback score 0.00", flush=True)
        score_str = "0.00"

    with lock:
        latest_score = score_str

    # Write debug file
    with open(SCORE_FILE, "w") as f:
        f.write(latest_score + "\n")

    print("[DEBUG] latest_score saved as", latest_score, flush=True)
    print("==============================", flush=True)


# ===================================
# BACKGROUND THREAD
# ===================================
def score_updater_loop():
    while True:
        compute_score_once()
        time.sleep(INTERVAL)


# ===================================
# HTTP HANDLER
# ===================================
class ScoreHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            body = latest_score + "\n"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        return  # silence logs


# ===================================
# MAIN
# ===================================
def main():
    print("[DEBUG] Starting NGFW score server...", flush=True)
    print("[DEBUG] Base directory:", BASE_DIR, flush=True)
    print("[DEBUG] Using script:", SCRIPT_PATH, flush=True)

    compute_score_once()  # initial run

    # Start updater thread
    t = threading.Thread(target=score_updater_loop, daemon=True)
    t.start()

    # Start HTTP server
    server = HTTPServer((HOST, PORT), ScoreHandler)
    print(f"[DEBUG] HTTP server listening on {HOST}:{PORT}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DEBUG] Shutting down...", flush=True)


if __name__ == "__main__":
    main()
