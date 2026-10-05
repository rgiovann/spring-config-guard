"""Listens on 127.0.0.1 at the given port and appends one line per connection to the given file:
"TLS" when the client's first bytes are a TLS handshake record (0x16 0x03), "HTTP" when they are a
plain HTTP request, with "+token" when the request carries the given Vault token in the clear. A
plain request is answered with 404, so the client gives up quickly."""
import socket
import sys
import threading

out_file, port, token = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
lock = threading.Lock()


def handle(conn):
    conn.settimeout(5)
    try:
        data = conn.recv(4096)
    except OSError:
        data = b""
    if data[:2] == b"\x16\x03":
        kind = "TLS"
    elif data[:4] in (b"GET ", b"PUT ", b"POST", b"HEAD", b"LIST"):
        kind = "HTTP" + ("+token" if token in data else "")
        try:
            body = b'{"errors":[]}'
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
                         + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except OSError:
            pass
    else:
        kind = "other:" + data[:8].hex()
    conn.close()
    with lock, open(out_file, "a") as f:
        f.write(f"{kind}\n")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen()
while True:
    connection, _ = server.accept()
    threading.Thread(target=handle, args=(connection,), daemon=True).start()
