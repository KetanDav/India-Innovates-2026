#!/usr/bin/env python
import os
import time
import threading
import subprocess
import sys

# Python2/3 HTTP compatibility
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

# ============= CONFIG =============
INTERVAL = 60
HOST = "0.0.0.0"
PORT = 8080

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(BASE_DIR, "endpointfff.sh")

SCORE_FILE = os.path.join(BASE_DIR, "endpoint_score_debug.txt")

latest_score = "0.00"
lock = threading.Lock()


# ===================================
# EXECUTE SCRIPT
# ===================================
def compute_score_once():
    global latest_score

    print("\n==============================")
    print("[DEBUG] Starting score calculation...")
    print("[DEBUG] SCRIPT_PATH =", SCRIPT_PATH)
    sys.stdout.flush()

    if not os.path.exists(SCRIPT_PATH):
        print("[ERROR] Script not found!")
        latest_score = "0.00"
        return

    # Ensure executable
    try:
        os.chmod(SCRIPT_PATH, 0o755)
    except:
        pass

    try:
        proc = subprocess.Popen(
            ["/bin/bash", SCRIPT_PATH],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = proc.communicate()

        # Decode safely
        try:
            stdout = stdout.decode("utf-8")
            stderr = stderr.decode("utf-8")
        except:
            pass

        print("[DEBUG] exit code:", proc.returncode)
        print("[DEBUG] stdout:", repr(stdout))
        print("[DEBUG] stderr:", repr(stderr))
        sys.stdout.flush()

        if proc.returncode != 0:
            raise Exception("Script failed")

        lines = stdout.strip().splitlines()
        if len(lines) == 0:
            raise Exception("No output from script")

        raw = lines[0].strip()
        print("[DEBUG] raw line =", raw)

        try:
            value = float(raw)
        except:
            print("[ERROR] Cannot parse float:", raw)
            value = 0.0

        value = max(0.0, min(1.0, value))
        score_str = "{:.2f}".format(value)

        print("[DEBUG] Parsed score =", score_str)

    except Exception as e:
        print("[EXCEPTION]", str(e))
        print("[DEBUG] Using fallback score 0.00")
        score_str = "0.00"

    with lock:
        latest_score = score_str

    try:
        with open(SCORE_FILE, "w") as f:
            f.write(latest_score + "\n")
    except:
        pass

    print("[DEBUG] latest_score saved as", latest_score)
    print("==============================")
    sys.stdout.flush()


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

        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        except:
            # Python2 fallback
            self.wfile.write(body)

    def log_message(self, format, *args):
        return


# ===================================
# MAIN
# ===================================
def main():
    print("[DEBUG] Starting NGFW score server...")
    print("[DEBUG] Base directory:", BASE_DIR)
    print("[DEBUG] Using script:", SCRIPT_PATH)
    sys.stdout.flush()

    compute_score_once()

    t = threading.Thread(target=score_updater_loop)
    t.daemon = True
    t.start()

    server = HTTPServer((HOST, PORT), ScoreHandler)
    print("[DEBUG] HTTP server listening on %s:%d" % (HOST, PORT))
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DEBUG] Shutting down...")


if __name__ == "__main__":
    main()
