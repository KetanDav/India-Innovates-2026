#!/usr/bin/env python3
import socket
import threading

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 5000        # change if needed


def recv_loop(conn):
    """Receive messages from client and print them."""
    while True:
        try:
            data = conn.recv(4096)
        except ConnectionResetError:
            print("\n[!] Connection reset by client.")
            break

        if not data:
            print("\n[!] Client disconnected.")
            break

        msg = data.decode(errors="ignore").rstrip()
        print(f"\nClient: {msg}")
        print("You: ", end="", flush=True)

    conn.close()
    print("[+] Connection closed. Exiting recv thread.")


def main():
    print(f"[+] Starting chat server on {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick restart on same port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print("[+] Waiting for connection...")

    conn, addr = sock.accept()
    print(f"[+] Connected by {addr}")

    # Start receiver thread
    t = threading.Thread(target=recv_loop, args=(conn,), daemon=True)
    t.start()

    try:
        while True:
            msg = input("You: ")
            if not msg:
                continue
            conn.sendall((msg + "\n").encode())
            if msg.lower() == "quit":
                print("[*] You closed th*]()
