#!/usr/bin/env python3
import socket

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 5000        # change if you want

def main():
    print(f"[+] Starting chat server on {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print("[+] Waiting for connection...")
    conn, addr = sock.accept()
    print(f"[+] Connected by {addr}")

    try:
        while True:
            # receive message
            data = conn.recv(4096)
            if not data:
                print("[!] Client disconnected")
                break

            msg = data.decode().strip()
            print(f"Client: {msg}")
            if msg.lower() == "quit":
                print("[*] Client requested to close chat.")
                break

            # send reply
            reply = input("You: ")
            conn.sendall((reply + "\n").encode())
            if reply.lower() == "quit":
                print("[*] You closed the chat.")
                break
    finally:
        conn.close()
        sock.close()
        print("[+] Server socket closed.")

if __name__ == "__main__":
    main()
