"""Stands in for an OAuth2 provider's token, JWK set and user-info endpoints, on 127.0.0.1 at the
given port, and appends one line per connection to the given file: "TLS" when the client's first
bytes are a TLS handshake record (0x16 0x03), else the request's method and path, with "+token"
when it carries the access token this listener issued.

POST /token answers a Bearer access token and, when the code the client sends isn't "-", an ID
token: the code is the nonce of the authorization request (the scenario script reads it from the
login redirect, where Spring Security already sends the hash of the nonce it keeps in the session),
and the ID token carries it as it is. The ID token is
RS256-signed with the given key, through openssl, for the subject scg-user (email
scg-user@scg.example). GET /jwks answers a JWK set with the public key read from the file named in
<dir>/jwks-key (the signing key, or another one); GET /userinfo answers the subject read from
<dir>/userinfo-sub, and the preferred_username (a claim the ID token doesn't carry) and the email
read from <dir>/userinfo-name, as "<name>" and "<name>@scg.example". Anything else is 404."""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

out_file, port, work_dir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
signing_key = os.path.join(work_dir, "signing-key.pem")
ACCESS_TOKEN = "scg-access-token"
lock = threading.Lock()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def read(name):
    with open(os.path.join(work_dir, name)) as f:
        return f.read().strip()


def jwks(key_file):
    modulus = subprocess.run(["openssl", "rsa", "-in", key_file, "-noout", "-modulus"],
                             capture_output=True, text=True, check=True).stdout.strip().split("=", 1)[1]
    n = bytes.fromhex(modulus)
    return {"keys": [{"kty": "RSA", "kid": "scg", "use": "sig", "alg": "RS256",
                      "n": b64url(n), "e": b64url((65537).to_bytes(3, "big"))}]}


def id_token(nonce):
    now = int(time.time())
    header = {"alg": "RS256", "kid": "scg", "typ": "JWT"}
    claims = {"iss": "https://provider.scg.example", "sub": "scg-user", "email": "scg-user@scg.example",
              "aud": ["scg-client"],
              "iat": now, "exp": now + 300,
              "nonce": nonce}
    signing_input = (b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(claims).encode())).encode()
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", signing_key],
                               input=signing_input, capture_output=True, check=True).stdout
    return signing_input.decode() + "." + b64url(signature)


def respond(conn, status, body):
    payload = json.dumps(body).encode()
    conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
                 + b"Content-Length: " + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)


def handle(conn):
    conn.settimeout(5)
    data = b""
    try:
        data = conn.recv(8192)
        head, _, body = data.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip() or 0)
                while len(body) < length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                    data += chunk
    except (OSError, ValueError):
        pass
    if data[:2] == b"\x16\x03":
        kind = "TLS"
    elif data[:4] in (b"GET ", b"POST"):
        head, _, body = data.partition(b"\r\n\r\n")
        method, target = head.split(b"\r\n", 1)[0].split(b" ")[:2]
        path = target.split(b"?", 1)[0].decode()
        kind = method.decode() + " " + path + ("+token" if b"Bearer " + ACCESS_TOKEN.encode() in head else "")
        try:
            if method == b"POST" and path == "/token":
                form = dict(p.split("=", 1) for p in body.decode().split("&") if "=" in p)
                token = {"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 300}
                if form.get("code", "-") != "-":
                    token["id_token"] = id_token(form["code"])
                respond(conn, b"200 OK", token)
            elif method == b"GET" and path == "/jwks":
                respond(conn, b"200 OK", jwks(os.path.join(work_dir, read("jwks-key"))))
            elif method == b"GET" and path == "/userinfo":
                respond(conn, b"200 OK", {"sub": read("userinfo-sub"), "preferred_username": read("userinfo-name"),
                                          "email": read("userinfo-name") + "@scg.example"})
            else:
                respond(conn, b"404 Not Found", {})
        except (OSError, subprocess.CalledProcessError):
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
