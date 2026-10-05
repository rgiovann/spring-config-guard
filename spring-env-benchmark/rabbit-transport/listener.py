"""Listens on the given ports and appends one line per connection to the given file: the port and
whether the client's first bytes were the plain AMQP protocol header ("AMQP") or a TLS handshake
record (0x16 0x03), then closes the connection."""
import socket
import sys
import threading

out_file, ports = sys.argv[1], [int(p) for p in sys.argv[2:]]
lock = threading.Lock()


def serve(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    while True:
        conn, _ = server.accept()
        conn.settimeout(5)
        try:
            first = conn.recv(8)
        except OSError:
            first = b""
        conn.close()
        if first.startswith(b"AMQP"):
            kind = "AMQP"
        elif first[:2] == b"\x16\x03":
            kind = "TLS"
        else:
            kind = "other:" + first.hex()
        with lock, open(out_file, "a") as f:
            f.write(f"{port}:{kind}\n")


for p in ports:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
