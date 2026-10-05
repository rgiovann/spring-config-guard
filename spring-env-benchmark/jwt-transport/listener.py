"""Listens on 127.0.0.1 at the given port and appends one line per connection to the given file:
"TLS" when the client's first bytes are a TLS handshake record (0x16 0x03), "HTTP" when they are a
plain HTTP request, with "+secret" when the request carries the given client secret, in the clear
or base64-encoded in a Basic Authorization header. A plain request is
answered with 404, so the client gives up quickly, except a GET for a path ending in ".pub" when a
key file is given: it is served, as a key server would."""
import base64
import socket
import sys
import threading

out_file, port, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
key_file = sys.argv[4] if len(sys.argv) > 4 else None
basic = base64.b64encode(b"scg-client:" + marker)
lock = threading.Lock()


def handle(conn):
    conn.settimeout(5)
    try:
        data = conn.recv(4096)
    except OSError:
        data = b""
    if data[:2] == b"\x16\x03":
        kind = "TLS"
    elif data[:4] in (b"GET ", b"PUT ", b"POST", b"HEAD"):
        kind = "HTTP" + ("+secret" if marker in data or basic in data else "")
        request_line = data.split(b"\r\n", 1)[0].split(b" ")
        serve_key = key_file and len(request_line) > 1 and request_line[1].endswith(b".pub")
        try:
            if serve_key:
                status, content_type, body = b"200 OK", b"text/plain", open(key_file, "rb").read()
            else:
                status, content_type, body = b"404 Not Found", b"application/json", b'{"errors":[]}'
            conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: " + content_type + b"\r\n"
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
