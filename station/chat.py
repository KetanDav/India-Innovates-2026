#!/usr/bin/env python3
import socket
import sys
import os

PORT = 5001
BUFFER = 4096
SAVE_DIR = "received_files"

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    print("[SERVER] Listening on 0.0.0.0:%d" % PORT)

    conn, addr = s.accept()
    print("[SERVER] Connection from %s:%d" % (addr[0], addr[1]))

    while True:
        data = conn.recv(BUFFER)
        if not data:
            break

        text = data.decode(errors="ignore")

        if text.startswith("FILE:"):
            parts = text.split(":", 2)
            filename = parts[1]
            filesize = int(parts[2])

            print("[SERVER] Receiving file: %s (%d bytes)" % (filename, filesize))
            with open(os.path.join(SAVE_DIR, filename), "wb") as f:
                remaining = filesize
                while remaining > 0:
                    chunk = conn.recv(min(BUFFER, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)

            print("[SERVER] File saved:", filename)
        else:
            print("[CLIENT]:", text)

    conn.close()
    s.close()
    print("[SERVER] Connection closed.")


def run_client(server_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[CLIENT] Connecting to %s:%d..." % (server_ip, PORT))
    s.connect((server_ip, PORT))
    print("[CLIENT] Connected. Type messages or SEND <filename> or EXIT.")

    while True:
        try:
            msg = input("> ")
        except EOFError:
            break

        if msg.upper().startswith("SEND "):
            filepath = msg.split(" ", 1)[1]
            if not os.path.isfile(filepath):
                print("[CLIENT] File not found:", filepath)
                continue

            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            header = "FILE:%s:%d" % (filename, filesize)
            s.send(header.encode())

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(BUFFER)
                    if not chunk:
                        break
                    s.send(chunk)

            print("[CLIENT] File sent:", filename)

        elif msg.upper() == "EXIT":
            print("[CLIENT] Closing connection.")
            s.close()
            break

        else:
            s.send(msg.encode())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 chat.py server")
        print("  python3 chat.py client <server_ip>")
        sys.exit(0)

    mode = sys.argv[1].lower()
    if mode == "server":
        run_server()
    elif mode == "client":
        if len(sys.argv) < 3:
            print("ERROR: No server IP provided.")
            print("Example: python3 chat.py client 192.168.1.10")
            sys.exit(1)
        run_client(sys.argv[2])
    else:
        print("ERROR: Invalid mode. Use 'server' or 'client'.")
