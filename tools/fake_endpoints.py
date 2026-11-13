#!/usr/bin/env python3
"""fake_endpoints.py - stand-ins for Gotify, the Apprise API, ntfy and a webhook.

    fake_endpoints.py --validate FILE...   check golden payloads (tests/golden)
                                           as each server would read them
    fake_endpoints.py --serve PORT LOG     answer all four APIs on 127.0.0.1:PORT,
                                           appending each request to LOG as JSON
                                           (one line each); for the agent's tests

What each validator checks is what the real server needs (Gotify's
/message with X-Gotify-Key and an integer priority, Apprise API's
/notify/<key> with title, body and type, ntfy's /<topic> with Title and
Priority headers, the webhook's documented event). The --serve mode can
also misbehave on request, for the retry tests: a path ending /fail503
answers 503 with Retry-After: 1, /fail401 answers 401, /hang never
answers.
"""
import json
import re
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

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        if self.path.endswith("/hang"):
            time.sleep(3600)
        if self.path.endswith("/fail503"):
            self.send_response(503)
            self.send_header("Retry-After", "1")
            self.end_headers()
            return
        if self.path.endswith("/fail401"):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized","errorCode":401}')
            return
        entry = {"path": self.path, "headers": dict(self.headers), "body": body.decode("utf-8", "replace")}
        try:
            entry["type"] = validate(self.path, dict(self.headers), body)
            status, reply = 200, b'{"id":1}'
        except (Invalid, ValueError, UnicodeDecodeError) as e:
            entry["invalid"] = str(e)
            status, reply = 400, json.dumps({"error": str(e)}).encode()
        with self.lock, open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


def main(argv):
    if len(argv) >= 2 and argv[1] == "--validate":
        return validate_golden(argv[2:])
    if len(argv) == 4 and argv[1] == "--serve":
        Handler.log_path = argv[3]
        ThreadingHTTPServer(("127.0.0.1", int(argv[2])), Handler).serve_forever()
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
