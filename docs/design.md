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
format per endpoint, enqueue, send, then commit the read position, so nothing is lost and
nothing is sent twice.

| Module | File | Pure |
|---|---|---|
| Parsers (from vmsotel) | `src/model/logparse.c` | yes |
| Rules and the defaults | `src/model/rules.c` | yes |
| Throttle | `src/model/throttle.c` | yes |
| Messages | `src/notify/format.c` | yes |
| Endpoint encoders | `src/notify/endpoint.c`, `json.c` | yes |
| Configuration | `src/agent/config.c` | yes |
| Log reader (from vmsotel) | `src/sources/vms/vms_logs.c` | no |
| HTTP, TLS, queue (from vmsotel) | `src/transport/` | no |
| Agent loop | `src/agent/agent.c` (phase 2) | no |

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
| opcom-request | OPCOM REQUEST | normal |

Everything else is quiet. User rules come first; the first match decides; a rule can
`ignore`. Audit type names are NSADEF's (`vn_nsa_type_name`). An OPCOM message's severity
is that of the first condition message in its text (vmsotel's parser).

## Throttle

Per rule and key (the record's user and remote node), the first event is sent at once and
opens a window (default 300 s); repeats inside it are counted, and one summary follows
when it ends ("19 more: Login failure ..."). A table entry that cannot be had means the
event is sent, never dropped.

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
group or world access; tokens never logged. TLS always verified, against `cafile` or the
system's CAs; there is no option to skip it. The audit parser never copies a password or
command-line packet (vmsotel's rule).

## Phases

1. **Core, Linux only** -- done: the copied code builds and its tests pass; rules,
   throttle, format, encoders, configuration, with tests and golden payloads checked by
   `tools/fake_endpoints.py`'s validators.
2. **Agent end to end on Linux** against `tools/fake_endpoints.py --serve` and real
   Gotify, apprise-api and ntfy containers on docker-nuc: delivery, retries, `Retry-After`,
   a down endpoint, TLS, summaries, `--test`, `--dry-run`.
3. **Probes on x86, IA64, Alpha**: the read position across process restarts, REPLY/LOG
   and NEW_LOG (D8 depends on it).
4. **VMS agent**: build procedures, an hour detached on each machine with induced events
   reaching Gotify.
5. **Kit** for X86VMS, I64VMS, AXPVMS; install, upgrade, remove; release.
