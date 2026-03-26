#!/usr/bin/env python3
import socket

SERVER_IP = "192.168.200.13"  # IP of PC1 (server's eth0 IP)
PORT = 5000                   # must match server

def main():
    print("[+] Connecting to {}:{}".format(SERVER_IP, PORT))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, PORT))
    print("[+] Connected! Type messages, Type 'quit' to exit.")

    try:
        while True:
            # send message
            msg = input("You: ")
            sock.sendall((msg + "\n").encode())
            if msg.lower() == "quit":
                print("[!] You closed the chat.")
                break

            # receive reply
            data = sock.recv(4096)
            if not data:
                print("[!] Server disconnected")
                break

            reply = data.decode().strip()
            print("Server:", reply)
            if reply.lower() == "quit":
                print("[!] Server closed the chat.")
                break

    finally:
        sock.close()

if __name__ == "__main__":
    main()
