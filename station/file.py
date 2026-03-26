#!/usr/bin/env python3

import socket
import threading
import argparse
import os
import sys

BUFFER_SIZE = 4096

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving file")
        data += chunk
    return data

def handle_receive(sock):
    buffer = b""
    while True:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                print("[*] Connection closed by peer")
                os._exit(0)
            buffer += chunk

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.decode("utf-8", errors="ignore")

                if line.startswith("MSG:"):
                    text = line[4:]
                    print("\n[PEER]: {}".format(text))
                    print("> ", end="", flush=True)

                elif line.startswith("FILE:"):
                    parts = line.split(":", 2)
                    if len(parts) != 3:
                        print("[!] Malformed FILE header")
                        continue

                    _, filename, size_str = parts
                    try:
                        size = int(size_str)
                    except:
                        print("[!] Invalid file size")
                        continue

                    filename = os.path.basename(filename) or "received.bin"
                    print("\n[*] Incoming file: {} ({} bytes)".format(filename, size))

                    data = recv_exact(sock, size)

                    out_name = "recv_{}".format(filename)
                    with open(out_name, "wb") as f:
                        f.write(data)

                    print("[*] Saved file as {}".format(out_name))
                    print("> ", end="", flush=True)

                else:
                    print("\n[?] Unknown line: {}".format(line))
                    print("> ", end="", flush=True)

        except Exception as e:
            print("\n[!] Receive error: {}".format(e))
            os._exit(1)

def handle_send(sock):
    print("Type messages and press Enter.")
    print("To send a file:")
    print("   /sendfile /path/to/file.bin")
    print()

    while True:
        try:
            msg = input("> ")
        except EOFError:
            break

        if not msg:
            continue

        if msg.startswith("/sendfile"):
            parts = msg.split(maxsplit=1)
            if len(parts) != 2:
                print("[!] Usage: /sendfile /path/to/file")
                continue

            path = parts[1].strip()
            if not os.path.isfile(path):
                print("[!] File not found: {}".format(path))
                continue

            try:
                filesize = os.path.getsize(path)
                filename = os.path.basename(path)

                header = "FILE:{}:{}\n".format(filename, filesize).encode("utf-8")
                sock.sendall(header)

                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        sock.sendall(chunk)

                print("[*] Sent file {} ({} bytes)".format(filename, filesize))

            except Exception as e:
                print("[!] Error sending file: {}".format(e))

        else:
            line = "MSG:{}\n".format(msg).encode("utf-8")
            try:
                sock.sendall(line)
            except Exception as e:
                print("[!] Send error: {}".format(e))
                break

def run_server(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print("[*] Server listening on {}:{}".format(host, port))
    conn, addr = srv.accept()
    print("[*] Connection from {}:{}".format(addr[0], addr[1]))

    t = threading.Thread(target=handle_receive, args=(conn,), daemon=True)
    t.start()

    handle_send(conn)

def run_client(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[*] Connecting to {}:{} ...".format(host, port))
    sock.connect((host, port))
    print("[*] Connected.")

    t = threading.Thread(target=handle_receive, args=(sock,), daemon=True)
    t.start()

    handle_send(sock)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["server", "client"], required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9009)
    args = p.parse_args()

    if args.mode == "server":
        run_server(args.host, args.port)
    else:
        run_client(args.host, args.port)

if __name__ == "__main__":
    main()
