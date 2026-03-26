#!/usr/bin/env python
import socket
import threading

HOST = "0.0.0.0"
PORT = 5000


def recv_loop(conn):
    """Receive messages from client and print them."""
    while True:
        try:
            data = conn.recv(4096)
        except Exception:
            print("\n[!] Error receiving data. Closing connection.")
            break

        if not data:
            print("\n[!] Client disconnected.")
            break

        try:
            msg = data.decode("utf-8", errors="ignore").rstrip()
        except Exception:
            msg = data.rstrip()

        print("\nClient: {}".format(msg))
        # re-show prompt
        print("You: ", end="")
        try:
            import sys
            sys.stdout.flush()
        except Exception:
            pass

    conn.close()
    print("[+] Connection closed. Exiting recv thread.")


def main():
    print("[+] Starting chat server on {}:{}".format(HOST, PORT))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print("[+] Waiting for connection...")

    conn, addr = sock.accept()
    print("[+] Connected by {}:{}".format(addr[0], addr[1]))

    t = threading.Thread(target=recv_loop, args=(conn,))
    t.daemon = True
    t.start()

    try:
        while True:
            try:
                msg = raw_input("You: ")  # Python 2
            except NameError:
                msg = input("You: ")      # Python 3

            if not msg:
                continue
            conn.sendall((msg + "\n").encode("utf-8"))
            if msg.lower() == "quit":
                print("[*] You closed the chat.")
                break
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt, closing.")
    finally:
        conn.close()
        sock.close()
        print("[+] Server socket closed.")


if __name__ == "__main__":
    main()
