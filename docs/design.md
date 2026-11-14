# vmsnotify design

## What it is for

OpenVMS writes what an operator most needs to know -- break-in attempts, login failures,
UAF and privilege changes, device errors, operator requests -- to the operator log (OPCOM)
and the security audit journal, where nobody sees it unless they look. vmsnotify reads
both as they are written and pushes what matters to notification servers the site runs
itself: **Gotify**, an **Apprise API** server (and through it mail, Teams, Matrix,
Pushover and the rest), **ntfy**, or any **webhook**. An agent on the VMS system connects
out to them directly. No third-party or cloud service is involved, and nothing listens.

## Decisions

| | Decision | Why |
|---|---|---|
| D1 | A project of its own, not a vmsotel feature | Alerting and telemetry are different jobs, wanted separately; each has its own kit and account |
| D2 | Start from a copy of vmsotel's log reader, parsers, transport, launcher and kit | They are proven on x86, IA64, Alpha and VAX (vmsotel findings 33–41, A19). Same author, MIT. Each copied file says where it came from; the copies may diverge |
| D3 | Gotify, Apprise API, ntfy, webhook | Gotify is the user's; the Apprise API reaches almost everything else without its destinations' secrets sitting on VMS; ntfy and a webhook cost little |
| D4 | Apprise through the Apprise API server's stored configuration (`POST /notify/<key>`) | No Python on VMS; the destinations and their secrets stay on the Apprise server |
| D5 | Default rules: security events and problems | A new install says something useful at once without being noisy |
| D6 | First release: x86-64, IA64, Alpha | TLS everywhere through VSI SSL3. VAX (plain HTTP, C89) later if wanted |
| D7 | Credentials only in headers and token files, never in a URL | Paths are logged; a URL with a query is refused |
| D8 | Remember the read position across restarts, with a cap | An alerting tool should not silently miss a break-in that happened while it was stopped (vmsotel starts at the end, which suits telemetry) |

## Pipeline

```
OPERATOR.LOG ─┐                ┌─ rules ─ throttle ─ format ─┬─ queue ─ gotify
              ├─ reader ─ parse┤                             ├─ queue ─ apprise
AUDIT JOURNAL ┘  (vmsotel)     └─ (pure, tested on Linux)    ├─ queue ─ ntfy
                                                             └─ queue ─ webhook
```

One loop: read a batch from both files, match each record against the rules, throttle,
format per endpoint, enqueue, commit the read position and save it, then send. A record
is dealt with once its message is queued or a rule has decided against it; what is queued
and not yet sent when the agent stops is logged as lost, as vmsotel does.

| Module | File | Pure |
|---|---|---|
| Parsers (from vmsotel) | `src/model/logparse.c` | yes |
| Rules and the defaults | `src/model/rules.c` | yes |
| Throttle | `src/model/throttle.c` | yes |
| Messages | `src/notify/format.c` | yes |
| Endpoint encoders | `src/notify/endpoint.c`, `json.c` | yes |
| Configuration | `src/agent/config.c` | yes |
| Log reader (from vmsotel) | `src/sources/vms/vms_logs.c`, `vms_sys.c` | no |
| Fake log source, for Linux | `src/sources/fake/fake_logs.c` | no |
| HTTP, TLS, queue (from vmsotel) | `src/transport/` | no |
| Platform (from vmsotel) | `src/platform/` | no |
| Agent loop | `src/agent/agent.c` | no |

## Default rules

| Rule | Matches | Priority |
|---|---|---|
| breakin | audit BREAKIN | urgent |
| login-failure | audit LOGFAIL | high |
| authorization | audit SYSUAF, RIGHTSDB | high |
| auditing | audit AUDIT, SERVER | high |
| privileged | audit PRVAUD, SYSTIME, SYSGEN, INSTALL | high |
| opcom-error | OPCOM with an `-E-` or `-F-` condition | high |
| opcom-warning | OPCOM with a `-W-` condition | normal |
| opcom-request | OPCOM REQUEST/REPLY (a numbered request) | normal |
| opcom-message | OPCOM message from any user but SYSTEM (a plain REQUEST is one: findings O2) | normal |

Everything else is quiet. User rules come first; the first match decides; a rule can
`ignore`. Audit type names are NSADEF's (`vn_nsa_type_name`). An OPCOM message's severity
is that of the first condition message in its text (vmsotel's parser).

## Throttle

Per rule and key, the first event is sent at once and opens a window (default 300 s);
repeats inside it are counted, and one summary follows when it ends ("19 more: Login
failure ..."). A table entry that cannot be had means the event is sent, never dropped.

**The key says who tried, from where**: the person, upper-cased -- the record's remote
username if it has one, else its username -- and the place, the remote node without a
leading service prefix: `IAIN from 192.168.0.131`. A prefix is `[A-Za-z_$]+:` with at least
one character that is not a hex digit, so `SSH_PASSWORD:192.168.0.131` loses it while
`FTP_C0A80083`, `192.168.0.5` and IPv6 (`fe80::1`, `2001:db8::1`, `abcd::1`) stay as they
are. Why: on the Alpha one failed SSH login writes two LOGFAIL records in the same second,
one as user IAIN (remote user `iain`, remote node `192.168.0.131`) and one as `SSH$SSH`
(remote user `IAIN`, remote node `SSH_PASSWORD:192.168.0.131`); x86 and IA64 write one, and
an older x86 sample had `SSH$SSH` with remote user `ROOT`. Keyed by username and the raw
remote node they were two groups, so two notifications and two summaries. The rules still
match on `vn_rec_user` and `vn_rec_remote` (the record's own fields), so a pattern such as
`*192.168.0.131` is unchanged; only the key is canonical.

**Twins are one event, silently.** An event with the same rule and key as one just admitted
(sent, or counted in a window), whose record time is within 2 s of that one's, is a
duplicate: not sent and not counted, so it makes no "1 more" either. Counting it would give
a summary for an attempt that was never repeated. It is the record's time, not the clock the
windows use, that decides, so a backlog read at once after a restart is judged as it
happened. The memory is a short list of recent events (32), not the windows, so it works for
a rule with `throttle = 0` too, which sends every event but not the twin. Records with no
time (0), and records that name no remote node (operator messages, local audit events), are
never twins: two operator errors from SYSTEM in one second are two events. The agent counts
duplicates in its final line ("2 duplicates") and logs nothing for each.
The cost is that two real attempts by one person from one place within 2 s are shown as one.

## Sending

Each endpoint has its own queue (`queue`, default 32 messages; the oldest is dropped when
it is full, and that is logged) and is sent to on its own, one connection per message.

| Answer | What the agent does |
|---|---|
| 2xx | Delivered |
| None, 429, 5xx | Kept; tried again after 1 s, doubling to 5 minutes, or after `Retry-After` (up to an hour) if that is longer |
| Anything else (401, 404) | Dropped, with the status, the path and the server's reason in the log: sending it again cannot help |

An endpoint that is down or hangs costs the others one `timeout` per attempt and nothing
more. At a stop the summaries of the open windows and a "stopped" notice are queued, each
queue gets one more try, and whatever is left is logged as lost.

The agent's own notices (`notices = yes`): started and stopped (low), a log that cannot
be read (high) or can be again (normal), records skipped at a start (high). They go to
every endpoint whose `min_priority` they meet.

`--test` sends one notice to every endpoint and prints each result. `--dry-run` prints
what would be sent and to which endpoints, sends nothing, reads no token file and leaves
the read position alone.

## The read position (D8)

The log source gives its committed position in each log as a one-line string, which the
agent keeps in a file (`--position`; by default the configuration's name with the type
`.pos`) and hands back at the next start. A source given one resumes there only if

- it still names the same file and the same record (VMS: the version's specification,
  its FID, and the record's RFA, length and first bytes), and
- what was written after it is within the limits: no more than `catchup.max_records`
  records, the oldest no older than `catchup.max_age`.

Otherwise it starts at the end, as it does with no saved position, and the agent sends a
notice saying what was skipped and why. The limits are all or nothing: one record too
old skips everything waiting. With either limit 0 there is no catching up.

On VMS the count is of what follows the saved record in that version plus, if the name
now leads to another version, all of that one. x86 has answered the question this rests
on (`probes/probe_position.c`): a saved specification and RFA find the same record from
another process, in the real logs; the FID's three words prove the file; a deleted
version fails with RMS$_FNF; OPERATOR.LOG has records of no length. IA64 and Alpha have
not been asked, and `vms_logs.c`'s own code for it has run only against `stub/`.

## Priorities

| vmsnotify | Gotify | ntfy | Apprise type |
|---|---|---|---|
| low | 2 | 2 | info |
| normal | 5 | 3 | info |
| high | 8 | 4 | warning |
| urgent | 10 | 5 | failure |

## Text

VMS text is 8-bit (DEC MCS, Latin-1 in its printable range). JSON and ntfy bodies are
made UTF-8; HTTP header values (ntfy's Title) are printable ASCII, with other characters
as `?` and line breaks as spaces, so no text can start a header of its own.

## Security

The agent's account: NETMBX, TMPMBX and READALL (both logs need it; vmsotel findings 27,
36), no WORLD, no login of any kind. Token files in `[CONF]`, owned by the account, no
group or world access; tokens never logged: the agent logs no request header, and a
server's answer only after anything equal to the endpoint's token, password or
basic-authentication value has been struck out of it. A token file must hold one
printable word; an empty one stops the start. TLS always verified, against `cafile` or the
system's CAs; there is no option to skip it. The audit parser never copies a password or
command-line packet (vmsotel's rule).

## Phases

1. **Core, Linux only** -- done: the copied code builds and its tests pass; rules,
   throttle, format, encoders, configuration, with tests and golden payloads checked by
   `tools/fake_endpoints.py`'s validators.
2. **Agent end to end on Linux** -- done against `tools/fake_endpoints.py`
   (`tools/agent_test.py`, in `make check`): all four endpoint types delivered and valid;
   credentials in headers only; `to` and `min_priority`; a 503 with `Retry-After` kept and
   sent again; a 401 dropped without a retry; a hanging endpoint and one that is down
   while the others get theirs; a full queue; TLS verified against the right CA and
   refused against the wrong one and against the system's; a burst as one event and one
   summary; `--test`; `--dry-run`; stop file and SIGTERM; a restart resuming without loss
   or repeats, the catch-up limits, a replaced log; an unreadable log; token files; and no
   secret in any line the agent wrote. The VMS reader's position code runs the same way
   against `stub/`. Real Gotify, apprise-api and ntfy servers were reached later, from VMS
   (findings R1, T1), in throwaway containers whose compose file (`tools/test-endpoints/`)
   was removed after the release; it is in the history at v0.1.0.
3. **Probes on x86, IA64, Alpha**: the read position across process restarts, REPLY/LOG
   and NEW_LOG (D8 depends on it). x86 has answered the first ("The read position");
   IA64 and Alpha have not.
4. **VMS agent**: build procedures, the node name from `SYI$_NODENAME`
   (`vn_platform_node` gives the TCP/IP host name until then), where the position file
   lives and its version limit, an hour detached on each machine with induced events
   reaching Gotify.
5. **Kit** for X86VMS, I64VMS, AXPVMS; install, upgrade, remove; release.
