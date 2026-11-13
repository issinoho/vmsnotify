#!/usr/bin/env python3
"""fake_endpoints.py - stand-ins for Gotify, the Apprise API, ntfy and a webhook.

    fake_endpoints.py --validate FILE...   check golden payloads (tests/golden)
                                           as each server would read them
    fake_endpoints.py [--bind ADDR] --serve PORT LOG [TLSDIR]
                                           answer all four APIs on 127.0.0.1:PORT,
                                           appending each request to LOG as JSON
                                           (one line each); with TLSDIR, over TLS
                                           with a self-signed certificate made
                                           there (server.crt is the CA to give
                                           the agent as cafile)

What each validator checks is what the real server needs (Gotify's
/message with X-Gotify-Key and an integer priority, Apprise API's
/notify/<key> with title, body and type, ntfy's /<topic> with Title and
Priority headers, the webhook's documented event).

The server can also misbehave, by the request's path, for the agent's
tests (tools/agent_test.py, which imports this file and starts it with
start()):
    .../fail503/...   503 with Retry-After: 1, always
    .../flaky/...     the answers in Handler.script first, one each --
                      (status, Retry-After or None) -- then as normal
    .../fail401/...   401 with Gotify's error body
    .../echo401/...   401 with a body that quotes the request's
                      credentials back, as a careless server might
    .../hang/...      no answer (until Handler.release is set)
Every request is kept in Handler.seen, with the time it came.
"""
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRIORITIES = {"low", "normal", "high", "urgent"}


class Invalid(Exception):
    pass


def need(cond, why):
    if not cond:
        raise Invalid(why)


def validate(path, headers, body):
    """Checks one request; returns the endpoint type it is for."""
    h = {k.lower(): v for k, v in headers.items()}
    ctype = h.get("content-type", "")
    for k, v in headers.items():
        need("\r" not in v and "\n" not in v, f"header {k} holds a line break")
        need(all(0x20 <= ord(c) < 0x7f for c in v), f"header {k} is not printable ASCII")
    text = body.decode("utf-8")              # every endpoint gets UTF-8
    if path.endswith("/message") and "x-gotify-key" in h:
        need(ctype.startswith("application/json"), "gotify: not JSON")
        m = json.loads(text)
        need(isinstance(m.get("message"), str) and m["message"], "gotify: no message")
        need(isinstance(m.get("title"), str), "gotify: title not a string")
        need(isinstance(m.get("priority"), int) and 0 <= m["priority"] <= 10,
             "gotify: priority not an integer 0-10")
        need(h["x-gotify-key"], "gotify: empty X-Gotify-Key")
        return "gotify"
    if re.search(r"/notify/[^/]+$", path):
        need(ctype.startswith("application/json"), "apprise: not JSON")
        m = json.loads(text)
        need(isinstance(m.get("body"), str) and m["body"], "apprise: no body")
        need(m.get("type") in ("info", "success", "warning", "failure"), "apprise: bad type")
        need(m.get("format", "text") in ("text", "markdown", "html"), "apprise: bad format")
        return "apprise"
    if ctype.startswith("text/plain"):
        need("title" in h, "ntfy: no Title header")
        need(h.get("priority") in ("1", "2", "3", "4", "5"), "ntfy: Priority not 1-5")
        need(re.fullmatch(r"/[-_A-Za-z0-9/]+", path), "ntfy: bad topic path")
        return "ntfy"
    need(ctype.startswith("application/json"), "webhook: not JSON")
    m = json.loads(text)
    need(m.get("kind") in ("event", "summary", "notice"), "webhook: bad kind")
    for k in ("node", "title", "message"):
        need(isinstance(m.get(k), str), f"webhook: {k} missing")
    need(m.get("priority") in PRIORITIES, "webhook: bad priority")
    if m["kind"] == "summary":
        need(isinstance(m.get("count"), int) and m["count"] > 0, "webhook: summary without count")
    if "record" in m:
        r = m["record"]
        need(r.get("source") in ("audit", "opcom"), "webhook: record source")
        need(isinstance(r.get("attributes"), dict), "webhook: record attributes")
        need(re.fullmatch(r"[0-9]+", r.get("time_unix_ns", "")), "webhook: time_unix_ns")
    return "webhook"


def validate_golden(files):
    bad = 0
    for f in files:
        raw = open(f, "rb").read()
        head, _, body = raw.partition(b"\n\n")
        lines = head.decode("ascii").replace("\r", "").split("\n")
        method, path = lines[0].split(" ", 1)
        headers = dict(l.split(": ", 1) for l in lines[1:] if l)
        body = body[:-1] if body.endswith(b"\n") else body   # the file's own newline
        try:
            need(method == "POST", "not a POST")
            kind = validate(path, headers, body)
            print(f"ok    {f} ({kind})")
        except (Invalid, ValueError, UnicodeDecodeError) as e:
            print(f"FAIL  {f}: {e}")
            bad += 1
    return 1 if bad else 0


class Handler(BaseHTTPRequestHandler):
    log_path = None
    lock = threading.Lock()
    seen = []                   # every request: a dict, "at" is time.monotonic()
    script = []                 # answers for .../flaky/..., consumed in order
    release = threading.Event() # set to let .../hang/... requests go

    def log_message(self, *a):
        pass

    def answer(self, status, reply=b"", retry_after=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        self.send_header("Content-Length", str(len(reply)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        entry = {"path": self.path, "headers": dict(self.headers),
                 "body": body.decode("utf-8", "replace"), "at": time.monotonic()}
        parts = self.path.split("/")
        with self.lock:
            self.seen.append(entry)
            scripted = self.script.pop(0) if "flaky" in parts and self.script else None
        if "hang" in parts:
            entry["status"] = 0
            self.release.wait(60)
            return
        if scripted is not None:
            entry["status"] = scripted[0]
            self.answer(scripted[0], b'{"error":"scripted"}', scripted[1])
            return
        if "fail503" in parts:
            entry["status"] = 503
            self.answer(503, b'{"error":"down for maintenance"}', 1)
            return
        if "fail401" in parts:
            entry["status"] = 401
            self.answer(401, b'{"error":"Unauthorized","errorCode":401,'
                             b'"errorDescription":"you need to provide a valid access token"}')
            return
        if "echo401" in parts:
            entry["status"] = 401
            creds = " ".join(v for k, v in self.headers.items()
                             if k.lower() in ("x-gotify-key", "authorization"))
            self.answer(401, json.dumps({"error": "bad credentials: " + creds}).encode())
            return
        try:
            entry["type"] = validate(self.path, dict(self.headers), body)
            status, reply = 200, b'{"id":1,"message":"stored"}'
        except (Invalid, ValueError, UnicodeDecodeError) as e:
            entry["invalid"] = str(e)
            status, reply = 400, json.dumps({"error": str(e)}).encode()
        entry["status"] = status
        if self.log_path:
            with self.lock, open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        self.answer(status, reply)


def make_cert(d, name="server"):
    """A self-signed certificate for 127.0.0.1 in d: NAME.crt and NAME.key."""
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/CN=fake-endpoints",
         "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", os.path.join(d, name + ".key"),
         "-out", os.path.join(d, name + ".crt")],
        check=True, capture_output=True)
    return os.path.join(d, name + ".crt")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass                    # a refused TLS handshake is the client's news


def start(port=0, tls_dir=None, bind="127.0.0.1"):
    """Starts a server in a thread; returns it and its port."""
    srv = Server((bind, port), Handler)
    if tls_dir:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(tls_dir, "server.crt"),
                            os.path.join(tls_dir, "server.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def main(argv):
    bind = "127.0.0.1"
    if len(argv) >= 3 and argv[1] == "--bind":
        bind = argv[2]
        argv = argv[:1] + argv[3:]
    if len(argv) >= 2 and argv[1] == "--validate":
        return validate_golden(argv[2:])
    if len(argv) in (4, 5) and argv[1] == "--serve":
        Handler.log_path = argv[3]
        if len(argv) == 5:
            print("CA certificate for cafile:", make_cert(argv[4]))
        start(int(argv[2]), argv[4] if len(argv) == 5 else None, bind)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
