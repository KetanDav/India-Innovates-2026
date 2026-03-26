#!/usr/bin/env python3
import os
import time
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

# ====== CONFIG ======
INTERVAL = 60          # seconds between recalculations
HOST = "0.0.0.0"       # listen on all interfaces
PORT = 8080            # HTTP port
# Path to your bash script (same dir as this .py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(BASE_DIR, "endpointfff.sh")

# ====== GLOBAL STATE ======
latest_score = "0.00"
lock = threading.Lock()


def compute_score_once():
    """
    Run endpointfff.sh once, parse first line as float 0–1,
    store into latest_score.
    """
    global latest_score
    try:
        # run script, capture stdout
        out = subprocess.check_output(
            [SCRIPT_PATH],
            stderr=subprocess.DEVNULL,
            text=True
        )
        line = out.strip().splitlines()[0].strip()
        val = float(line)

        # clamp to 0–1 just in case
        if val < 0.0:
            val = 0.0
        if val > 1.0:
            val = 1.0

        score_str = f"{val:.2f}"
    except Exception:
        # on any error, set to 0.00
        score_str = "0.00"

    with lock:
        latest_score = score_str


def score_updater_loop():
    """
    Background thread: update score every INTERVAL seconds.
    """
    while True:
        compute_score_once()
        time.sleep(INTERVAL)


class ScoreHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Always return *last* stored score (no recalculation here)
        with lock:
            body = latest_score + "\n"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    # Disable default noisy logging
    def log_message(self, format, *args):
        return


def main():
    # Initial calculation so first request has real value
    compute_score_once()

    # Start background updater
    t = threading.Thread(target=score_updater_loop, daemon=True)
    t.start()

    # Start HTTP server
    server = HTTPServer((HOST, PORT), ScoreHandler)
    print(f"[+] Score server running on {HOST}:{PORT}")
    print("[+] Score is updated every", INTERVAL, "seconds")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down server...")


if __name__ == "__main__":
    main()
