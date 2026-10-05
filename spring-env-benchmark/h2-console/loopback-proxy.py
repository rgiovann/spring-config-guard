"""A minimal reverse proxy on the given address that forwards every GET to localhost, as a proxy or
sidecar on the same machine does: the app then sees each request as coming from loopback."""
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

listen_host, listen_port, target_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])


class Forward(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            response = urllib.request.urlopen(f"http://localhost:{target_port}{self.path}")
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", response.headers.get("Content-Type", "text/html"))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer((listen_host, listen_port), Forward).serve_forever()
