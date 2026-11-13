# CLAUDE.md — vmsnotify

vmsnotify reads the OpenVMS operator log and security audit journal and sends what
matters to Gotify, an Apprise API server, ntfy or a webhook that the site runs itself.
`docs/design.md` is the design and its decisions; read it first.

**Status:** phase 1 (core, Linux only) is done. Nothing has run on VMS yet.

## Where it comes from

Much of the code is copied from vmsotel (`~/projects/vmsotel`, `issinoho/vmsotel`, MIT,
same author): the log parsers, the VMS log reader, HTTP/TLS/queue, the platform layer,
the stub. Each copied file's second line names its origin; prefixes are `vn_`/`VN_` for
vmsotel's `vo_`/`VO_`. Comments citing "vmsotel findings N" refer to vmsotel's
`docs/findings.md`, which holds the evidence. vmsotel's `CLAUDE.md` has the OpenVMS
lessons; the ones that matter here are repeated below.

## Build and test

```sh
make check     # rules, throttle, format, endpoint encoders against tests/golden/,
               # configuration (with the shipped example), golden payloads through
               # tools/fake_endpoints.py's validators, the VMS reader against stub/
make golden    # rewrite tests/golden/ from the encoders; read the diff before committing
```

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
- **No secrets in URLs or logs.** Tokens in headers and token files only.
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
