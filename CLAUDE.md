# CLAUDE.md — vmsnotify

vmsnotify reads the OpenVMS operator log and security audit journal and sends what
matters to Gotify, an Apprise API server, ntfy or a webhook that the site runs itself.
`docs/design.md` is the design and its decisions; read it first.

**Status:** phases 1 (core) and 2 (the agent end to end on Linux) are done. On x86 the
agent builds (`build_vms.com`, both images, no warnings) and dry-runs against the real logs
(`docs/findings.md`, B1-B3); from there it has sent to a
stand-in for the four servers, resumed from its saved position, and delivered real login
failures and a break-in within seconds (B4-B8). IA64 gives the same, with no source change
(findings, "IA64"). So does the Alpha, where one failed SSH login
makes two audit records, so two notifications (findings, "Alpha"). `--test` reaches the
real Gotify, Apprise API and ntfy from all three (R1). Not yet: TLS, an operator-log
record, running detached, the kit.
Induced login failures count towards VMS's break-in evasion: six from one source in a few
minutes made an INTRUDER record on x86. Keep to three, and say so first. The read position across restarts (D8) is implemented in the
fake source and in `vms_logs.c`; the latter has run only against `stub/`. x86's probe says
what it rests on holds there (`docs/design.md`, "The read position"); IA64 and Alpha have
not been asked. Phase 2 was not run against the real containers on docker-nuc.

## Where it comes from

Much of the code is copied from vmsotel (`~/projects/vmsotel`, `issinoho/vmsotel`, MIT,
same author): the log parsers, the VMS log reader, HTTP/TLS/queue, the platform layer,
the stub. Each copied file's second line names its origin; prefixes are `vn_`/`VN_` for
vmsotel's `vo_`/`VO_`. Comments citing "vmsotel findings N" refer to vmsotel's
`docs/findings.md`, which holds the evidence. vmsotel's `CLAUDE.md` has the OpenVMS
lessons; the ones that matter here are repeated below.

## Build and test

```sh
make check     # unit tests: rules, throttle, format, endpoint encoders against
               # tests/golden/, configuration (with the shipped example), HTTP answers;
               # golden payloads through tools/fake_endpoints.py's validators; then
               # tools/agent_test.py: the three agents end to end (about a minute)
make golden    # rewrite tests/golden/ from the encoders; read the diff before committing

build/vmsnotify CONF [--test | --dry-run] [--cycles N] [--position FILE] ...
```

`build/vmsnotify` has the fake log source, `build/vmsnotify_tls` adds TLS,
`build/vmsnotify_vmsstub` has the VMS reader against `stub/` (it tests the reader's logic,
not what RMS does). The fake source reads the file named by `VMSNOTIFY_FAKE_LOG_FILE`,
one record a line (`src/sources/fake/fake_logs.c` has the format), which is how
`agent_test.py` says what the logs hold and when. A new end-to-end check must be seen to
fail without what it checks.

C99 with `-pedantic -Wall -Wextra -Werror`; the VMS sources drop only `-pedantic` (for
`$`). Do not weaken that. A golden payload changes only on purpose.

## The machines

x86 (`USER$ROOT:[IAIN.VMSNOTIFY]`), IA64 (the same) and the Alpha (`DISK$WORK:[IAIN.VMSNOTIFY]`)
take SSH key login as IAIN: `tools/vms.sh x86|ia64|alpha` (copy `tools/nodes.conf.example`
to the git-ignored `tools/nodes.conf`). Run anything over a minute as `vms.sh NODE batch
PROC.COM`: interactive SSH sessions lose long runs, worst on the Alpha. IAIN has every
privilege by default on the Alpha. Ask before anything system-wide (PRODUCT INSTALL,
AUTHORIZE, SYSTARTUP) or that reaches the operators (REQUEST). Test endpoints:
containers on docker-nuc (192.168.0.218), which the user runs; there is no SSH to it.

## Hard constraints

- **C99, VSI C**; no C11, no C++. `vn_u64` only through the `vn_q*` operations,
  `vn_snprintf`, `vn_qstr` (vmsotel's VAX discipline; keeps VAX possible later).
- **Pure modules do no I/O** (rules, throttle, format, encoders, config, parsers), so they
  are tested here.
- **Item lists assume 32-bit pointers**; code linking OpenSSL's `..._SHR32` uses
  `/POINTER_SIZE=32`.
- **No secrets in URLs or logs.** Tokens in headers and token files only. Never pass a
  request header to the log; a server's answer goes through `scrub` first (`agent.c`).
  `agent_test.py` searches every line every run wrote for each secret.
- **TLS is always verified.** No option to skip it.

## OpenVMS lessons (from vmsotel and vms-beszel)

- Probe before building: a header declaring something proves nothing.
- Undefined symbols are LINK *warnings*: check `$SEVERITY` after every LINK.
- A new source file touches three build files: Makefile, `build_vms.com`, `descrip.mms`.
- DCL `.EQ.`/`.NE.` compare numbers: use `.EQS.`/`.NES.` for strings (vmsotel A13).
- On Alpha, `$GETRMI`'s FRLIST/MODLIST are longwords; C defaults to G_FLOAT (use IEEE).
- OPCOM writes OPERATOR.LOG minutes late: 10–11 on Alpha and VAX (vmsotel A19, V17).
- An SSH public-key login as an unknown user makes no audit record (vmsotel A19): induce
  login failures with a password.

## Commits

Stage files by name; never `git add -A`. Explain why, and record what was verified and
how; say plainly what has not run on VMS. Don't push without the user asking.
