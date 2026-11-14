# vmsnotify

OpenVMS's operator log and security audit journal, as notifications on your phone.

vmsnotify reads OPCOM and the audit journal as they are written and sends what matters --
break-in attempts, login failures, authorization and privilege changes, device errors,
operator requests -- to notification servers you run yourself:

- **[Gotify](https://gotify.net)**
- an **[Apprise API](https://github.com/caronc/apprise-api)** server, and through it mail,
  Teams, Matrix, Pushover and the rest of [Apprise's destinations](https://github.com/caronc/apprise/wiki)
- **[ntfy](https://ntfy.sh)**
- any **webhook** (Node-RED, n8n, Home Assistant, your own script)

The agent connects out to them directly. No third-party or cloud service is involved,
and nothing listens on the VMS system.

> **Status:** in development. The agent runs end to end on Linux, with a stand-in for the
> two logs: rules, throttling, the four endpoint formats, retries, TLS, and a read
> position that survives a restart, all tested against a local stand-in for the four
> servers. Nothing has run on OpenVMS yet ([`docs/design.md`](docs/design.md), "Phases").

## What it sends by default

| Event | Priority |
|---|---|
| Break-in attempt (audit BREAKIN) | urgent |
| Login failure (LOGFAIL) | high |
| UAF or rights database change; auditing changed; privilege use, system time, SYSGEN, INSTALL | high |
| OPCOM message with an `-E-` or `-F-` condition | high |
| OPCOM message with a `-W-` condition; an operator REQUEST; any OPCOM message from a user other than SYSTEM | normal |

Logins, logouts and routine OPCOM traffic stay quiet. Your own rules come first: silence a
monitoring host's login failures, raise anything mentioning shadow sets, send some events
only to some endpoints. A burst of the same event becomes one message and one summary
("19 more: Login failure ...").

## Configuration

See [`vmsnotify.conf.example`](vmsnotify.conf.example):

```
[endpoint home]
type       = gotify
url        = https://gotify.example.com
token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN

[rule monitoring-host]
source = audit
types  = LOGFAIL
remote = *192.168.0.131
action = ignore
```

## Building and testing (Linux)

```sh
make check                                   # needs python3 and OpenSSL (headers and the openssl command)

build/vmsnotify my.conf --test               # one notice to every endpoint
build/vmsnotify my.conf --dry-run            # print what would be sent
build/vmsnotify my.conf                      # run (on Linux the logs are made up)
```

`build/vmsnotify_tls` is the same with https. `tools/fake_endpoints.py --serve PORT LOG`
answers as all four servers would, for trying a configuration without them.

## Running detached on OpenVMS (source tree)

After `@build_vms`, make `VMSNOTIFY.CONF` beside the procedures (from `vmsnotify.conf.example`), then:

```
@dev:[dir.VMSNOTIFY]VMSNOTIFY_START     RUN/DETACHED as you, privileges NETMBX, TMPMBX, READALL
TYPE dev:[dir.VMSNOTIFY]VMSNOTIFY.LOG    the agent's log; VMSNOTIFY_RUN.LOG is DCL's
@dev:[dir.VMSNOTIFY]VMSNOTIFY_STOP      creates VMSNOTIFY.STOP and waits for the process to end
```

## The PCSI kit

`@[.vmsnotify.kit]MAKE_KIT`, after `build_vms`, writes
`ISSINOHO-<base>-VMSNOTIFY-V0.1-0.PCSI` into `[.KIT_<arch>]` for X86VMS, I64VMS or AXPVMS
(each needs VSI's SSL3 kit; there is no VAX kit). Installed, the agent runs as its own
account, not SYSTEM, started by persona (`VMSNOTIFY_LAUNCH.EXE`), with NETMBX, TMPMBX and
READALL only. The tree is `VMSNOTIFY$ROOT:` with `[BIN]`, `[COM]`, `[DOC]` and, owned by the
account with no group or world access, `[CONF]` (configuration and token files), `[DATA]`
(the read position) and `[LOG]`. `VMSNOTIFY$CONFIGURE` makes the account and the protections;
`VMSNOTIFY$STARTUP` and `$SHUTDOWN` go in `SYSTARTUP_VMS.COM` and `SYSHUTDWN.COM`.
`VMSNOTIFY_START`, `_RUN` and `_STOP` serve both layouts. `docs/operations.md` has the
steps; `tools/check_kit.py`, in `make check`, fails if the product description and
`kit/make_kit.com` drift. The kit has been packaged on x86; it has not yet been installed.

## Licence

MIT; see [LICENSE](LICENSE). Parts come from [vmsotel](https://github.com/issinoho/vmsotel),
by the same author under the same licence.
