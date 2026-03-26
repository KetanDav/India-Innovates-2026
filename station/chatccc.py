#!/usr/bin/env python3
import socket
import threading
import sys

# Use: python3 chat_client.py <SERVER_IP> [PORT]
# Example: python3 chat_client.py 192.168.100.10 5000


def recv_loop(sock):
    """Receive messages from server and print them."""
    while True:
        try:
            data = sock.recv(4096)
        except ConnectionResetError:
            print("\n[!] Connection reset by server.")
            break

        if not data:
            print("\n[!] Server disconnected.")
            break

        msg = data.decode(errors="ignore").rstrip()
        print(f"\nServer: {msg}")
        print("You: ", end="", flush=True)

    sock.close()
    print("[+] Socket closed. Exiting recv thread.")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <SERVER_IP> [PORT]")
        sys.exit(1)

    server_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    print(f"[+] Connecting to {server_ip}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    print("[+] Connected to server.")

    # Start receiver thread
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()

    try:
        while True:
            msg = input("You: ")
            if not msg:
                continue
            sock.sendall((msg + "\n").encode())
            if msg.lower() == "quit":
                print("[*] You closed the chat.")
                break
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt, closing.")
    finally:
        sock.close()
        print("[+] Client socket closed.")


if __name__ == "__main__":
    main()
