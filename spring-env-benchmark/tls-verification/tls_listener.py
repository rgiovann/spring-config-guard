"""Listens with TLS on the given ports and appends one line per connection to the given file: the
port and whether the client finished the handshake ("accepted") or aborted it ("refused", with the
alert the client sent), then closes the connection. Each port presents its own certificate:
  port:certfile:keyfile [port:certfile:keyfile ...]"""
import socket
import ssl
import sys
import threading

out_file, specs = sys.argv[1], sys.argv[2:]
lock = threading.Lock()


def record(port, result):
    with lock, open(out_file, "a") as f:
        f.write(f"{port}:{result}\n")


def serve(port, certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    while True:
        conn, _ = server.accept()
        conn.settimeout(5)
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                try:
                    tls.recv(1)
                    record(port, "accepted")
                except ssl.SSLError as e:
                    record(port, "refused:" + (e.reason or str(e)))
                except OSError:
                    record(port, "accepted")
        except ssl.SSLError as e:
            record(port, "refused:" + (e.reason or str(e)))
        except OSError as e:
            record(port, "closed:" + type(e).__name__)


for spec in specs:
    port, certfile, keyfile = spec.split(":")
    threading.Thread(target=serve, args=(int(port), certfile, keyfile), daemon=True).start()
threading.Event().wait()
