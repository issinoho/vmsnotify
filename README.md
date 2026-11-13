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
| OPCOM message with a `-W-` condition; operator REQUEST | normal |

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

## Licence

MIT; see [LICENSE](LICENSE). Parts come from [vmsotel](https://github.com/issinoho/vmsotel),
by the same author under the same licence.
