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

> **Status:** in development. The core -- rules, throttling, messages, the four endpoint
> formats, the configuration -- is written and tested on Linux. The agent itself, and
> anything on OpenVMS, comes next ([`docs/design.md`](docs/design.md), "Phases").

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
make check
```

## Licence

MIT; see [LICENSE](LICENSE). Parts come from [vmsotel](https://github.com/issinoho/vmsotel),
by the same author under the same licence.
