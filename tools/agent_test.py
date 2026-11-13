#!/usr/bin/env python3
"""agent_test.py - the agent end to end, against fake_endpoints.py.

    agent_test.py build/vmsnotify build/vmsnotify_tls build/vmsnotify_vmsstub

Runs the real agent binaries against a local server that answers as
Gotify, the Apprise API, ntfy and a webhook would, and looks at both
ends: what the server received and what the agent logged. The fake log
source reads a file this test writes (VMSNOTIFY_FAKE_LOG_FILE; see
src/sources/fake/fake_logs.c), so what "the logs" hold, and when, is the
test's to say -- including while the agent is stopped.

The last section runs the VMS log reader against stub/vmsstub.c. That
tests the reader's logic (a saved position taken apart, the limits, a
file that is not the one saved), not what RMS does on VMS.

Every secret the configurations use is searched for in every line the
agent wrote, in all of the runs.
"""
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I leaves it out
import fake_endpoints as fe  # noqa: E402

H = fe.Handler

GOTIFY_TOKEN = "AbCdGotifyTokenXyZ"
NTFY_TOKEN = "tk_ntfySecretToken0123"
HOOK_USER = "hookuser"
HOOK_PASS = "hookSecretPassw0rd"
HOOK_BASIC = base64.b64encode(f"{HOOK_USER}:{HOOK_PASS}".encode()).decode()
SECRETS = [GOTIFY_TOKEN, NTFY_TOKEN, HOOK_PASS, HOOK_BASIC]

failures = 0
checks = 0
all_output = []                 # everything any agent run wrote


def check(name, cond, detail=""):
    global failures, checks
    checks += 1
    print(f"{'ok  ' if cond else 'FAIL'}  {name}")
    if not cond:
        failures += 1
        if detail:
            print(detail)


def reset():
    with H.lock:
        H.seen.clear()
        H.script.clear()
    H.release.set()             # let go of anything a last test left hanging
    H.release = fe.threading.Event()


def seen(part=None, status=None):
    with H.lock:
        return [e for e in H.seen
                if (part is None or part in e["path"].split("/"))
                and (status is None or e.get("status") == status)]


def hooks():
    """The webhook's accepted events, decoded, in the order they came."""
    return [json.loads(e["body"]) for e in seen("hook", 200)]


class Box:
    """One test's files: a configuration, the fake logs, a position."""

    def __init__(self, d, name):
        self.dir = os.path.join(d, name)
        os.makedirs(self.dir)
        self.conf = os.path.join(self.dir, "vmsnotify.conf")
        self.pos = os.path.join(self.dir, "vmsnotify.pos")
        self.log = os.path.join(self.dir, "fake.log")
        self.token = os.path.join(self.dir, "gotify.token")
        with open(self.token, "w") as f:
            f.write("  " + GOTIFY_TOKEN + "\r\n\n")     # trimmed by the agent
        open(self.log, "w").close()

    def write_conf(self, port, extra="", scheme="http", gotify="", hook="/hook",
                   endpoint_extra="", only=None, rules=""):
        base = f"{scheme}://127.0.0.1:{port}"
        eps = {
            "g": f"[endpoint g]\ntype = gotify\nurl = {base}{gotify}\n"
                 f"token_file = {self.token}\n",
            "a": f"[endpoint a]\ntype = apprise\nurl = {base}\nkey = vms\n",
            "n": f"[endpoint n]\ntype = ntfy\nurl = {base}\ntopic = openvms\n"
                 f"token = {NTFY_TOKEN}\n",
            "w": f"[endpoint w]\ntype = webhook\nurl = {base}{hook}\n"
                 f"user = {HOOK_USER}\npassword = {HOOK_PASS}\n",
        }
        text = "interval = 1\nnode = TESTVMS\nnotices = no\n" + extra
        for k in only or "ganw":
            text += "\n" + eps[k] + "timeout = 2\n" + endpoint_extra
        text += "\n" + rules
        with open(self.conf, "w") as f:
            f.write(text)

    def append(self, *lines):
        with open(self.log, "a") as f:
            for line in lines:
                f.write(line + "\n")

    def from_start(self):
        """A saved position before the first record: everything in the
        log counts as written while stopped."""
        with open(self.pos, "w") as f:
            f.write(f"opcom = fake1 0 0 {self.log}\naudit = fake1 0 0 {self.log}\n")

    def run(self, binary, cycles=2, drain=4, args=(), env=None, timeout=60):
        e = dict(os.environ, VMSNOTIFY_FAKE_LOG_FILE=self.log)
        e.update(env or {})
        cmd = [binary, self.conf, "--position", self.pos]
        if cycles:
            cmd += ["--cycles", str(cycles), "--drain", str(drain)]
        p = subprocess.run(cmd + list(args), capture_output=True, text=True,
                           timeout=timeout, env=e)
        all_output.append(p.stdout + p.stderr)
        return p.returncode, p.stdout + p.stderr


def logfail(user="ROOT", remote="SSH_PASSWORD:192.0.2.10", when=0):
    return f"{when}|audit|LOGFAIL|{user}|{remote}"


def apart(n, user="ROOT", remote="SSH_PASSWORD:192.0.2.10"):
    """n login failures that are separate attempts: record times 3 s apart,
    ending a few seconds ago. (The same person and place within 2 s are one
    attempt's twin records, and the throttle drops all but one: the Alpha.)"""
    now = int(time.time())
    return [logfail(user, remote, when=now - 3 * (n - i)) for i in range(n)]


def opcom_error(n, when=0):
    return (f"{when}|opcom|Message from user SYSTEM on TESTVMS\\n"
            f"%MOUNT-F-MEDOFL, medium is offline, drive {n}")


def titles(events):
    return [e["title"] for e in events]


def main(plain, tls, vmsstub):
    d = tempfile.mkdtemp(prefix="vmsnotify-test-")
    srv, port = fe.start()

    # ---- delivery -------------------------------------------------------
    reset()
    b = Box(d, "delivery")
    b.write_conf(port, extra="notices = yes\n")
    b.append(logfail(), opcom_error(1), "0|opcom|Message from user SYSTEM on "
             "TESTVMS\\nroutine traffic, no condition", "0|audit|LOGIN|IAIN|")
    b.from_start()
    rc, out = b.run(plain)
    got = seen()
    by = {t: [e for e in got if e.get("type") == t]
          for t in ("gotify", "apprise", "ntfy", "webhook")}
    check("delivery: every endpoint type gets started, two events and "
          "stopped, each valid as its server reads it",
          rc == 0 and all(len(v) == 4 for v in by.values()) and
          not any("invalid" in e for e in got) and len(got) == 16, out)
    h = hooks()
    check("delivery: the webhook's events are a notice, the login failure, "
          "the operator error and a notice, in that order; the routine "
          "message and the login are not sent",
          [e["kind"] for e in h] == ["notice", "event", "event", "notice"] and
          h[1]["rule"] == "login-failure" and h[1]["priority"] == "high" and
          h[1]["record"]["source"] == "audit" and
          h[1]["title"] == "TESTVMS: Login failure: remote user ROOT from "
                           "SSH_PASSWORD:192.0.2.10" and
          h[2]["rule"] == "opcom-error" and "MEDOFL" in h[2]["message"] and
          "started" in h[0]["title"] and "stopped" in h[3]["title"] and
          "4 records, 2 ignored, 2 events" in out, out + repr(h))
    hd = {t: {k.lower(): v for k, v in by[t][0]["headers"].items()}
          for t in by if by[t]}
    check("delivery: credentials in headers -- the token file's token "
          "trimmed, ntfy's bearer token, the webhook's basic authentication; "
          "none for apprise; User-Agent vmsnotify/0.1.0",
          rc == 0 and hd["gotify"].get("x-gotify-key") == GOTIFY_TOKEN and
          hd["ntfy"].get("authorization") == "Bearer " + NTFY_TOKEN and
          hd["webhook"].get("authorization") == "Basic " + HOOK_BASIC and
          "authorization" not in hd["apprise"] and
          all(x.get("user-agent") == "vmsnotify/0.1.0" for x in hd.values()) and
          not any("?" in e["path"] for e in got), repr(hd))
    check("delivery: ntfy's priority and gotify's are their own scales",
          rc == 0 and hd["ntfy"].get("priority") in ("2", "4") and
          [json.loads(e["body"])["priority"] for e in by["gotify"]] == [2, 8, 8, 2],
          repr(by["gotify"]))

    # ---- which endpoints ------------------------------------------------
    reset()
    b = Box(d, "routing")
    b.write_conf(port, only="gnw", endpoint_extra="",
                 rules="[rule ops]\nsource = opcom\nseverity = error\n"
                       "to = w\npriority = urgent\n\n"
                       "[rule quiet-host]\nsource = audit\ntypes = LOGFAIL\n"
                       "remote = *192.0.2.99\naction = ignore\n")
    with open(b.conf) as f:
        text = f.read().replace("topic = openvms\n",
                                "topic = openvms\nmin_priority = urgent\n")
    with open(b.conf, "w") as f:
        f.write(text)
    b.append(logfail(), opcom_error(1),
             logfail("NAGIOS", "SSH_PASSWORD:192.0.2.99"))
    b.from_start()
    rc, out = b.run(plain)
    check("routing: a rule's `to` names the only endpoint, min_priority "
          "keeps a high event from ntfy, a user rule ignores a host",
          rc == 0 and len(seen("message")) == 1 and len(seen("openvms")) == 0 and
          [e["rule"] for e in hooks()] == ["login-failure", "ops"] and
          "1 ignored, 2 events" in out, out)

    # ---- 503 with Retry-After, then success -----------------------------
    reset()
    H.script.append((503, 3))
    b = Box(d, "retry")
    b.write_conf(port, hook="/flaky/hook")
    b.append(logfail())
    b.from_start()
    rc, out = b.run(plain, cycles=2, drain=8)
    f = seen("flaky")
    check("503 with Retry-After: 3 -- kept, sent again after 3 s and no "
          "sooner, delivered once; the others were not held up",
          rc == 0 and [e["status"] for e in f] == [503, 200] and
          2.9 <= f[1]["at"] - f[0]["at"] < 5 and
          "w: failed, HTTP 503: scripted; retrying in 3000 ms; 1 waiting" in out and
          "w: sent again after 1 failed attempt" in out and
          len(seen("message", 200)) == 1 and
          seen("message")[0]["at"] - f[0]["at"] < 1, out)

    # ---- 401: dropped, not retried --------------------------------------
    reset()
    b = Box(d, "rejected")
    b.write_conf(port, gotify="/fail401")
    b.append(logfail(), opcom_error(1))
    b.from_start()
    rc, out = b.run(plain)
    check("401: each message tried once and dropped with the server's "
          "reason; the other endpoints get theirs; nothing is left unsent",
          rc == 0 and len(seen("fail401")) == 2 and len(hooks()) == 2 and
          out.count("g: REJECTED, HTTP 401 on /fail401/message: you need to "
                    "provide a valid access token -- message dropped; check "
                    "the endpoint's token") == 2 and
          "2 dropped, 0 unsent" in out, out)

    # ---- a server that quotes the credentials back ----------------------
    reset()
    b = Box(d, "echo")
    b.write_conf(port, gotify="/echo401", hook="/echo401/hook", only="gw")
    b.append(logfail())
    b.from_start()
    logfile = os.path.join(b.dir, "agent.log")
    rc, out = b.run(plain, args=["--log", logfile])
    with open(logfile) as f:
        text = f.read()
    all_output.append(text)
    check("a 401 whose body quotes the request's credentials: the log (in "
          "--log's file) has the reason with them struck out",
          rc == 0 and len(seen("echo401")) == 2 and
          "bad credentials: " + "*" * len(GOTIFY_TOKEN) in text and
          "bad credentials: Basic " + "*" * len(HOOK_BASIC) in text and
          not any(s in text + out for s in SECRETS), text + out)

    # ---- a hanging endpoint ---------------------------------------------
    reset()
    b = Box(d, "hang")
    b.write_conf(port, hook="/hang/hook")
    b.append(logfail(), opcom_error(1))
    b.from_start()
    t0 = time.monotonic()
    rc, out = b.run(plain, cycles=2, drain=5)
    took = time.monotonic() - t0
    check("a hanging endpoint: it times out and is retried, its messages "
          "are reported unsent (exit status non-zero); the other three get "
          "both of theirs",
          rc != 0 and "w: failed: no response within 2000 ms; retrying in "
          "1000 ms; 2 waiting" in out and
          "w: stopping with 2 messages unsent" in out and
          len(seen("message", 200)) == 2 and len(seen("vms", 200)) == 2 and
          len(seen("openvms", 200)) == 2 and took < 20, out)

    # ---- nothing listening ----------------------------------------------
    reset()
    b = Box(d, "down")
    b.write_conf(port, extra="queue = 2\n")
    with open(b.conf) as f:
        text = f.read().replace(f"127.0.0.1:{port}/hook", "127.0.0.1:1/hook")
    with open(b.conf, "w") as f:
        f.write(text)
    b.append(logfail(), opcom_error(1), opcom_error(2))
    b.from_start()
    rc, out = b.run(plain, cycles=2, drain=2)
    check("an endpoint that is down, queue = 2: the third message drops "
          "the oldest, and it is said; the others get all three",
          rc != 0 and "queue for w full (2); its oldest message is dropped" in out and
          "w: failed: connect: " in out and "w: stopping with 2 messages unsent" in out and
          len(seen("message", 200)) == 3, out)

    # ---- a burst --------------------------------------------------------
    reset()
    b = Box(d, "burst")
    b.write_conf(port, extra="rules.defaults.throttle = 2\n", only="gw")
    b.append(*apart(20))
    b.append(logfail("OTHER", "SSH_PASSWORD:192.0.2.77"))
    b.from_start()
    rc, out = b.run(plain, cycles=5)
    h = hooks()
    check("a burst of 20 identical login failures and one other: two "
          "events, then one summary of 19 when the 2 s window ends",
          rc == 0 and [e["kind"] for e in h] == ["event", "event", "summary"] and
          h[2]["count"] == 19 and h[2]["window_s"] == 2 and
          h[2]["title"] == "TESTVMS: 19 more: Login failure: remote user ROOT "
                           "from SSH_PASSWORD:192.0.2.10" and
          len(seen("message", 200)) == 3 and
          "2 events, 19 throttled, 1 summaries" in out, out + repr(titles(h)))

    reset()
    b = Box(d, "burst-flush")
    b.write_conf(port, only="w")
    b.append(*apart(5))
    b.from_start()
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("a burst whose 300 s window is still open at the stop: the "
          "summary is sent then",
          rc == 0 and [e["kind"] for e in h] == ["event", "summary"] and
          h[1]["count"] == 4, out)

    # The Alpha writes two records for one failed SSH login, in the same
    # second, as two different users: the person and the place are the same.
    reset()
    b = Box(d, "alpha-pair")
    b.write_conf(port, only="w")
    now = int(time.time())
    b.append(f"{now - 20}|audit|LOGFAIL|iain|192.168.0.131|IAIN",
             f"{now - 20}|audit|LOGFAIL|IAIN|SSH_PASSWORD:192.168.0.131|SSH$SSH",
             f"{now - 10}|audit|LOGFAIL|iain|192.168.0.131|IAIN",
             f"{now - 10}|audit|LOGFAIL|IAIN|SSH_PASSWORD:192.168.0.131|SSH$SSH",
             f"{now - 10}|audit|LOGFAIL|BOB|SSH_PASSWORD:192.168.0.131|SSH$SSH")
    b.from_start()
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("the Alpha's two records for one failed login are one event; "
          "a second attempt 10 s later is counted (one summary of 1, not 2), "
          "its twin dropped silently; another person is another event",
          rc == 0 and [e["kind"] for e in h] == ["event", "event", "summary"] and
          h[2]["count"] == 1 and "BOB" in h[1]["title"] and
          "2 events, 1 throttled, 1 summaries, 2 duplicates" in out, out + repr(h))

    # ---- --test ---------------------------------------------------------
    reset()
    b = Box(d, "test-ok")
    b.write_conf(port)
    with open(b.conf) as f:
        text = f.read().replace("topic = openvms\n",
                                "topic = openvms\nmin_priority = urgent\n")
    with open(b.conf, "w") as f:
        f.write(text)
    b.append(logfail())
    rc, out = b.run(plain, cycles=0, args=["--test"])
    check("--test: one notice to every endpoint whatever its min_priority, "
          "each result printed, exit status 0; no log is read and no "
          "position written",
          rc == 0 and len(seen(status=200)) == 4 and
          all(f"ok    {n} ({t}): HTTP 200" in out for n, t in
              (("g", "gotify"), ("a", "apprise"), ("n", "ntfy"), ("w", "webhook"))) and
          "ok: 0 of 4 endpoints failed" in out and not os.path.exists(b.pos) and
          all(e["kind"] == "notice" and e["title"] == "TESTVMS: vmsnotify test"
              for e in hooks()), out)

    reset()
    b = Box(d, "test-bad")
    b.write_conf(port, gotify="/fail401", hook="/fail503/hook")
    rc, out = b.run(plain, cycles=0, args=["--test"])
    check("--test with a bad token and a server that is down: both named "
          "with the reason, the other two ok, exit status non-zero",
          rc != 0 and "FAIL  g (gotify): HTTP 401 on /fail401/message: you "
          "need to provide a valid access token" in out and
          "FAIL  w (webhook): HTTP 503 on /fail503/hook: down for maintenance" in out and
          "ok    a (apprise): HTTP 200" in out and "ok    n (ntfy): HTTP 200" in out and
          "FAILED: 2 of 4 endpoints failed" in out, out)

    # ---- --dry-run ------------------------------------------------------
    reset()
    b = Box(d, "dry-run")
    b.write_conf(port, extra="notices = yes\n")
    os.remove(b.token)          # a dry run needs no token
    b.append(logfail(), opcom_error(1), "0|audit|LOGIN|IAIN|")
    b.from_start()
    with open(b.pos) as f:
        before = f.read()
    rc, out = b.run(plain, cycles=1, args=["--dry-run"])
    with open(b.pos) as f:
        after = f.read()
    check("--dry-run: the messages are printed with their endpoints, "
          "nothing is sent, the saved position is left alone",
          rc == 0 and len(seen()) == 0 and before == after and
          "--- event, priority high, rule login-failure, to: g, a, n, w\n"
          "TESTVMS: Login failure: remote user ROOT from SSH_PASSWORD:192.0.2.10\n" in out and
          "--- event, priority high, rule opcom-error, to: g, a, n, w\n" in out and
          "Event: LOGFAIL\n" in out and "--- notice, priority low, to: g, a, n, w\n"
          "TESTVMS: vmsnotify started" in out and "DRY RUN" in out and
          out.count("--- event") == 2, out)

    # ---- the read position across restarts ------------------------------
    reset()
    b = Box(d, "restart")
    b.write_conf(port, only="w")
    b.append(logfail("A1"), opcom_error(1))
    rc, out = b.run(plain, cycles=1)
    check("first start, no saved position: it starts at the end; what was "
          "there before is not sent; the position is saved",
          rc == 0 and len(seen()) == 0 and os.path.exists(b.pos) and
          "starting at the end of the fake operator log (1 records)" in out, out)

    b.append(logfail("A2"), opcom_error(2), logfail("A3"))
    rc, out = b.run(plain, cycles=1)
    h1 = titles(hooks())
    check("restart: the three records written while it was stopped are "
          "sent, in order, and nothing older",
          rc == 0 and len(h1) == 3 and "A2" in h1[0] and "drive 2" in h1[1] and
          "A3" in h1[2] and "resuming the fake audit journal at its saved "
          "position: 2 records written while stopped" in out, out + repr(h1))

    rc, out = b.run(plain, cycles=2)
    check("restart again with nothing new: nothing is sent twice",
          rc == 0 and len(hooks()) == 3, out)

    # Stopped by its stop file while running, then more is written.
    stop = os.path.join(b.dir, "stop")
    e = dict(os.environ, VMSNOTIFY_FAKE_LOG_FILE=b.log)
    p = subprocess.Popen([plain, b.conf, "--position", b.pos, "--stop-file", stop],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=e)
    time.sleep(1.5)
    b.append(*apart(3, "B1"))
    time.sleep(2.0)
    open(stop, "w").close()
    try:
        out, _ = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        out += "\n(killed: it did not stop)"
    all_output.append(out)
    h = hooks()[3:]
    check("running, then stopped by its stop file: an event read while "
          "running and, at the stop, the summary of its open window; the "
          "stop file is deleted; exit status 0",
          p.returncode == 0 and not os.path.exists(stop) and
          [x["kind"] for x in h] == ["event", "summary"] and h[1]["count"] == 2 and
          "stop requested" in out and "to stop: create " + stop in out and
          "0 unsent" in out, out)

    b.append(logfail("C1"))
    p = subprocess.Popen([plain, b.conf, "--position", b.pos],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=e)
    time.sleep(1.5)
    p.send_signal(signal.SIGTERM)
    try:
        out, _ = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    all_output.append(out)
    h = titles(hooks()[5:])
    check("started again and stopped by SIGTERM: only the record written "
          "since is sent",
          p.returncode == 0 and len(h) == 1 and "C1" in h[0] and
          "stop requested" in out, out + repr(h))

    # The limits.
    reset()
    b.write_conf(port, extra="notices = yes\ncatchup.max_records = 3\n", only="w")
    b.append(*[logfail(f"D{i}") for i in range(5)])
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("restart with 5 records waiting and catchup.max_records = 3: "
          "none is sent, a notice says they were skipped",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          h[1]["priority"] == "high" and
          h[1]["title"] == "TESTVMS: vmsnotify skipped log records" and
          "5 records were written while vmsnotify was stopped, more than "
          "catchup.max_records (3)" in h[1]["message"] and
          "audit journal" in out, out + repr(h))

    reset()
    b.write_conf(port, extra="notices = yes\ncatchup.max_age = 600\n", only="w")
    now = int(time.time())
    b.append(logfail("E1", when=now - 3000), logfail("E2", when=now - 5))
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("restart with a record 3000 s old waiting and catchup.max_age = "
          "600: skipped, with a notice",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "the oldest of 2 records" in h[1]["message"] and
          "more than catchup.max_age (600)" in h[1]["message"], out + repr(h))

    reset()
    b.append(logfail("F1", when=now - 300))
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("restart with a record 300 s old waiting: within the limit, sent "
          "with its own time",
          rc == 0 and [x["kind"] for x in h] == ["notice", "event", "notice"] and
          "F1" in h[1]["title"] and
          h[1]["record"]["time_unix_ns"] == str(now - 300) + "000000000",
          out + repr(h))

    reset()
    with open(b.log, "w") as f:
        f.write(logfail("G1") + "\n" + logfail("G2") + "\n")
    rc, out = b.run(plain, cycles=1)
    h = hooks()
    check("restart with the log replaced by another: the saved position "
          "does not fit it, so it starts at the end and says so",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "the record at the saved position is not the one saved" in h[1]["message"],
          out + repr(h))

    reset()
    with open(b.pos, "w") as f:
        f.write("this is not a position file\n")
    b.append(logfail("H1"))
    rc, out = b.run(plain, cycles=1)
    check("a position file that holds no position: as a first start",
          rc == 0 and [x["kind"] for x in hooks()] == ["notice", "notice"] and
          "(none saved yet)" in out, out)

    # ---- a log that cannot be read --------------------------------------
    reset()
    b = Box(d, "unreadable")
    b.write_conf(port, extra="notices = yes\n", only="w")
    b.append(opcom_error(1), logfail())
    b.from_start()
    rc, out = b.run(plain, cycles=3, env={"VMSNOTIFY_FAKE_LOG_FAIL": "1"})
    h = hooks()
    check("the audit journal unreadable: said once in the log and in one "
          "notice; the operator log's event is still sent",
          rc == 0 and out.count("logs: cannot read SYS$MANAGER:SECURITY."
                                "AUDIT$JOURNAL: fake: no privilege") == 1 and
          [x["kind"] for x in h] == ["notice", "notice", "event", "notice"] and
          h[1]["title"] == "TESTVMS: vmsnotify cannot read a log" and
          h[1]["priority"] == "high" and h[2]["rule"] == "opcom-error", out + repr(h))

    # ---- what stops a start ---------------------------------------------
    reset()
    b = Box(d, "empty-token")
    b.write_conf(port)
    with open(b.token, "w") as f:
        f.write(" \n\n")
    rc, out = b.run(plain, cycles=1)
    check("an empty token file: the agent does not start, and says which",
          rc != 0 and f"not starting: endpoint g: token_file {b.token} is empty" in out and
          len(seen()) == 0, out)
    with open(b.token, "w") as f:
        f.write(GOTIFY_TOKEN + "\nX-Injected: yes\n")
    rc, out = b.run(plain, cycles=1)
    check("a token file with a second line: refused, its content not quoted",
          rc != 0 and "holds more than one printable word" in out and
          "Injected" not in out and len(seen()) == 0, out)
    os.remove(b.token)
    rc, out = b.run(plain, cycles=1)
    check("a token file that is not there: refused",
          rc != 0 and "cannot be opened" in out, out)
    b = Box(d, "https-plain")
    b.write_conf(port, scheme="https")
    rc, out = b.run(plain, cycles=1)
    check("https in the image built without TLS: refused at the start",
          rc != 0 and "built without TLS" in out, out)
    srv.shutdown()

    # ---- TLS ------------------------------------------------------------
    reset()
    certs = os.path.join(d, "certs")
    os.makedirs(certs)
    ca = fe.make_cert(certs)
    other = fe.make_cert(certs, "other")
    srv, tport = fe.start(tls_dir=certs)
    b = Box(d, "tls")
    b.write_conf(tport, scheme="https", endpoint_extra=f"cafile = {ca}\n")
    b.append(logfail(), opcom_error(1))
    b.from_start()
    rc, out = b.run(tls)
    got = seen()
    check("TLS, the server's certificate as cafile: verified, all four "
          "endpoint types delivered",
          rc == 0 and len(got) == 8 and not any("invalid" in e for e in got) and
          "endpoint g: TLS through OpenSSL" in out and "0 unsent" in out, out)

    reset()
    rc, out = b.run(tls, cycles=0, args=["--test"])
    check("TLS: --test says what was negotiated",
          rc == 0 and "ok    g (gotify): HTTP 200, TLSv1." in out, out)

    reset()
    b = Box(d, "tls-wrong-ca")
    b.write_conf(tport, scheme="https", endpoint_extra=f"cafile = {other}\n",
                 only="gw")
    b.append(logfail())
    b.from_start()
    rc, out = b.run(tls, cycles=1, drain=2)
    check("TLS, another certificate as cafile: refused -- nothing reaches "
          "the server, the log says why, the message is kept and reported "
          "unsent",
          rc != 0 and len(seen()) == 0 and "g: failed: TLS certificate" in out and
          "g: stopping with 1 message unsent" in out, out)

    reset()
    b = Box(d, "tls-system-ca")
    b.write_conf(tport, scheme="https", only="w")
    b.append(logfail())
    b.from_start()
    rc, out = b.run(tls, cycles=1, drain=2)
    check("TLS, no cafile: a self-signed certificate is refused against "
          "the system's CAs (there is no way to skip the check)",
          rc != 0 and len(seen()) == 0 and "w: failed: TLS certificate" in out, out)

    reset()
    b = Box(d, "tls-plain-server")
    b.write_conf(port, scheme="https", only="w", endpoint_extra=f"cafile = {ca}\n")
    with open(b.conf) as f:
        text = f.read().replace(f":{port}", f":{tport}").replace("https", "http")
    with open(b.conf, "w") as f:
        f.write(text)
    b.append(logfail())
    b.from_start()
    rc, out = b.run(tls, cycles=1, drain=2)
    check("plain http to the TLS port: fails, and is kept for a retry",
          rc != 0 and len(seen()) == 0 and "w: failed" in out, out)
    srv.shutdown()

    # ---- the VMS reader against the stub --------------------------------
    srv, port = fe.start()
    vms_reader(d, vmsstub, port)
    srv.shutdown()

    # ---- no secret in anything the agent wrote --------------------------
    text = "\n".join(all_output)
    check(f"no token, password or basic-authentication value in any of "
          f"the {len(all_output)} runs' output ({len(text.splitlines())} lines)",
          len(text) > 5000 and not any(s in text for s in SECRETS) and
          "Authorization" not in text and "X-Gotify-Key" not in text)

    print(f"\nagent_test: {checks} checks, {failures} failed")
    if failures:
        print(f"the runs' files are kept in {d}")
    else:
        shutil.rmtree(d, ignore_errors=True)
    return 1 if failures else 0


# One audit record as x86's journal has them (stub/vmsstub.c): a LOGFAIL,
# three packets; the stub's journal is records with a two-byte length.
JOURNAL_REC = bytes([
    0x05, 0x00, 0x04, 0x00, 0x1c, 0x00, 0x03, 0x00,
    0x38, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
    0x0c, 0x00, 0x06, 0x00]) + b"SECURITY" + bytes([0x0c, 0x00, 0x03, 0x00]) + \
    b"SECURITY" + bytes([0x0c, 0x00, 0x31, 0x00]) + b"FTA6574:"


def vms_reader(d, vmsstub, port):
    """The VMS log reader with stub/vmsstub.c for RMS: the stub keeps its
    two files in build/ under the current directory, so each run has the
    box's directory as its own."""
    reset()
    b = Box(d, "vmsstub")
    os.makedirs(os.path.join(b.dir, "build"))
    oplog = os.path.join(b.dir, "build", "stub_operator.log")
    journal = os.path.join(b.dir, "build", "stub_audit.journal")
    b.write_conf(port, extra="notices = yes\n", only="w")
    vmsstub = os.path.abspath(vmsstub)

    def run(cycles=3):
        p = subprocess.run([vmsstub, b.conf, "--position", b.pos, "--cycles",
                            str(cycles), "--drain", "4"], capture_output=True,
                           text=True, timeout=60, cwd=b.dir)
        all_output.append(p.stdout)
        return p.returncode, p.stdout

    def opcom(text, when=None):
        t = time.gmtime(when if when is not None else time.time())
        mon = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC"[3 * t.tm_mon - 3:3 * t.tm_mon]
        with open(oplog, "a") as f:
            f.write(f"%%%%%%%%%%%  OPCOM  {t.tm_mday:2d}-{mon}-{t.tm_year} "
                    f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.00  %%%%%%%%%%%\n"
                    f"Message from user SYSTEM on STUBBY\n{text}\n")

    def audit(n=1):
        with open(journal, "ab") as f:
            for _ in range(n):
                f.write(bytes([len(JOURNAL_REC), 0]) + JOURNAL_REC)

    def position():
        with open(b.pos) as f:
            return f.read()

    rc, out = run(1)
    first = position()
    check("VMS reader (stub), first start: at the end of both files, "
          "nothing sent but the notices; a position saved for each, with "
          "file specification, FID and RFA",
          rc == 0 and [x["kind"] for x in hooks()] == ["notice", "notice"] and
          "starting at the end of STUBBY$DKA0:[SYS0.SYSMGR]OPERATOR.LOG;1" in out and
          "opcom = rms1 STUBBY$DKA0:[SYS0.SYSMGR]OPERATOR.LOG;1 " in first and
          "audit = rms1 STUBBY$DKA0:[SYS0.SYSCOMMON.SYSMGR]SECURITY.AUDIT$JOURNAL;1 "
          in first and " R " in first, out + first)

    reset()
    audit(2)
    opcom("%MOUNT-F-MEDOFL, medium is offline, written while stopped")
    rc, out = run(3)
    h = hooks()
    check("VMS reader (stub), restart: resumes at the saved position in "
          "both; the operator message and the login failures written while "
          "stopped are sent (the two identical failures as one event and a "
          "summary), nothing older",
          rc == 0 and [x["kind"] for x in h] ==
          ["notice", "event", "event", "summary", "notice"] and
          sorted(x.get("rule") for x in h[1:3]) == ["login-failure", "opcom-error"] and
          h[3]["count"] == 1 and
          "resuming in STUBBY$DKA0:[SYS0.SYSMGR]OPERATOR.LOG;1 at the saved "
          "position (1 records written while stopped)" in out and
          "AUDIT$JOURNAL;1 at the saved position (2 records written while "
          "stopped)" in out and position() != first, out + repr(h))

    reset()
    rc, out = run(2)
    check("VMS reader (stub), restart with nothing new: nothing sent twice",
          rc == 0 and [x["kind"] for x in hooks()] == ["notice", "notice"] and
          "(0 records written while stopped)" in out, out)

    reset()
    opcom("%MOUNT-F-MEDOFL, medium is offline, two hours ago", time.time() - 7200)
    rc, out = run(3)
    h = hooks()
    check("VMS reader (stub), an operator message two hours old waiting, "
          "catchup.max_age 3600: skipped with a notice",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "SYS$MANAGER:OPERATOR.LOG: the oldest of 1 records" in h[1]["message"] and
          "more than catchup.max_age (3600)" in h[1]["message"], out + repr(h))

    reset()
    b.write_conf(port, extra="notices = yes\ncatchup.max_records = 4\n", only="w")
    audit(5)
    rc, out = run(2)
    h = hooks()
    check("VMS reader (stub), 5 journal records waiting, "
          "catchup.max_records 4: skipped with a notice",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "more than catchup.max_records (4)" in h[1]["message"], out + repr(h))

    # Another file under the same name: written beside it and renamed
    # over it, so that it cannot be given the old one's inode.
    reset()
    with open(journal + ".new", "wb") as f:
        with open(journal, "rb") as g:
            f.write(g.read())
        f.write(bytes([len(JOURNAL_REC), 0]) + JOURNAL_REC)
    os.replace(journal + ".new", journal)
    rc, out = run(2)
    h = hooks()
    check("VMS reader (stub), the journal replaced by a file with the same "
          "name and content: the FID differs, so the position is not "
          "trusted; skipped with a notice",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "is not the file it was" in h[1]["message"], out + repr(h))

    reset()
    saved = position()
    with open(b.pos, "w") as f:
        f.write(saved.replace("audit = rms1 ", "audit = rms9 "))
    audit(1)
    rc, out = run(2)
    h = hooks()
    check("VMS reader (stub), a saved position it cannot take apart: "
          "skipped with a notice, the operator log still resumed",
          rc == 0 and [x["kind"] for x in h] == ["notice"] * 3 and
          "the saved read position cannot be understood" in h[1]["message"] and
          "resuming in STUBBY$DKA0:[SYS0.SYSMGR]OPERATOR.LOG;1" in out, out + repr(h))

    # A new version while stopped: the saved one is finished, the new
    # one is read from its start.
    reset()
    with open(journal + ".2", "wb") as f:
        f.write(bytes([len(JOURNAL_REC), 0]) + JOURNAL_REC)
    rc, out = run(3)
    h = hooks()
    check("VMS reader (stub), a new version of the journal begun while "
          "stopped: counted against the limits, then read from its start",
          rc == 0 and [x["kind"] for x in h] == ["notice", "event", "notice"] and
          "AUDIT$JOURNAL;1 is finished; now reading" in out and
          "AUDIT$JOURNAL;2" in position(), out + repr(h))

    # OPERATOR.LOG has records of no length (x86), and the last record
    # of the file, where a first start leaves its position, can be one.
    reset()
    os.remove(b.pos)
    with open(oplog, "a") as f:
        f.write("\n")
    rc, out = run(1)
    saved = [line for line in position().splitlines() if line.startswith("opcom")]
    opcom("%MOUNT-F-MEDOFL, medium is offline, after the empty record")
    rc2, out2 = run(3)
    h = hooks()
    check("VMS reader (stub), a position at a record of no length: saved "
          "with an empty head, and resumed from",
          rc == 0 and rc2 == 0 and len(saved) == 1 and saved[0].endswith(" 0 -") and
          [x["kind"] for x in h] == ["notice", "notice", "notice", "event", "notice"] and
          "after the empty record" in h[3]["message"] and
          "OPERATOR.LOG;1 at the saved position (1 records written while "
          "stopped)" in out2, out + out2 + repr(saved))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
