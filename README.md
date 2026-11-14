<p align="center">
  <img src="docs/images/banner.svg" alt="vmsnotify: a DECterm window creating the agent's account, starting it as that account, and showing its log sending a login failure to Gotify, Apprise and ntfy, beside a mark of log lines gathered into one line to a bell" width="100%">
</p>

# vmsnotify

[![Release](https://img.shields.io/github/v/release/issinoho/vmsnotify?label=release)](https://github.com/issinoho/vmsnotify/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/issinoho/vmsnotify/total?label=downloads)](https://github.com/issinoho/vmsnotify/releases)
![OpenVMS](https://img.shields.io/badge/OpenVMS-IA64%20%7C%20x86--64%20%7C%20Alpha-blue)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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

![Gotify showing vmsnotify's messages from two OpenVMS systems: X86VMS and AXPBOX starting, and a high-priority SYSUAF change on AXPBOX with its event, user, image, time, node and rule](docs/images/gotify.png)

> **Status:** [0.1.0](https://github.com/issinoho/vmsnotify/releases/tag/v0.1.0) is
> released, with PCSI kits for OpenVMS **x86-64**, **IA64** and **Alpha**. Each has run
> detached for an hour sending to real Gotify, Apprise API and ntfy servers over verified TLS,
> and its kit has been installed, started at boot by its startup procedure, removed and
> reinstalled ([`docs/findings.md`](docs/findings.md)).

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

## Installing

Download the kit for your system from the
[release](https://github.com/issinoho/vmsnotify/releases/latest). As SYSTEM:

```
$ SET FILE/ATTRIBUTE=(RFM:FIX,LRL:8192,MRS:8192,RAT:NONE) ISSINOHO-*-VMSNOTIFY-V0001-0-1.PCSI
$ PRODUCT INSTALL VMSNOTIFY /PRODUCER=ISSINOHO /SOURCE=dev:[dir]
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE
```

Set your endpoints in `VMSNOTIFY$ROOT:[CONF]VMSNOTIFY.CONF` (below), then check them and
start the agent:

```
$ vmsnotify := $VMSNOTIFY$ROOT:[BIN]VMSNOTIFY_TLS.EXE
$ vmsnotify "VMSNOTIFY$ROOT:[CONF]VMSNOTIFY.CONF" "--test"
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_START
```

`--test` sends one message to each endpoint and says what each answered. For boots, add
`@SYS$STARTUP:VMSNOTIFY$STARTUP.COM` to `SYSTARTUP_VMS.COM` after TCP/IP and
`@SYS$STARTUP:VMSNOTIFY$SHUTDOWN.COM` to `SYSHUTDWN.COM`, and answer YES to "start the agent
at boot" in `VMSNOTIFY$CONFIGURE`. [`docs/operations.md`](docs/operations.md) has the rest.

## Configuration

[`vmsnotify.conf.example`](vmsnotify.conf.example) explains every setting. Each server is
an `[endpoint NAME]` section, and every notification goes to every endpoint unless a rule
or the endpoint's `min_priority` says otherwise.

**Tokens go in files**, not in the configuration: a file in `VMSNOTIFY$ROOT:[CONF]` holding
just the token, which only the agent's account can read:

```
$ CREATE VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
AbCdEf123456789
^Z
$ SET FILE/OWNER=VMSNOTIFY/PROTECTION=(S:RWED,O:RWED,G,W) VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
```

**TLS is always verified.** With no `cafile`, against the system's certificate store. The
stores on our test systems differ: the Alpha's verified a Let's Encrypt certificate, while
x86 and IA64 needed Let's Encrypt's roots (ISRG Root X1 and X2, in PEM) given as `cafile`.
For a server with a self-signed or private-CA certificate, `cafile` is that certificate or
its CA's.

### Gotify

In Gotify, create an application (Apps, Create application), and put its token in a file.

```
[endpoint gotify]
type       = gotify
url        = https://gotify.example.com
token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
# cafile   = VMSNOTIFY$ROOT:[CONF]ISRG_ROOTS.PEM
```

Priorities map to Gotify's 2 (low), 5 (normal), 8 (high) and 10 (urgent), so the app can
treat login failures and break-ins differently from the routine.

### ntfy

A topic on your own ntfy server. With access control on, make a user that may publish to
the topic and give it a token (`ntfy token add USER`, a `tk_...` value):

```
[endpoint phone]
type         = ntfy
url          = https://ntfy.example.com
topic        = openvms
token_file   = VMSNOTIFY$ROOT:[CONF]NTFY.TOKEN
min_priority = high
```

`min_priority = high` keeps the phone for login failures, break-ins and errors. ntfy gets
the title and priority (2 to 5) as headers, and the tag `openvms` with `warning` or
`rotating_light` for high and urgent. Basic authentication (`user`, `password`) works too.

### Apprise API: mail, Matrix, Teams, Pushover, Telegram, Discord, Slack...

An [Apprise API](https://github.com/caronc/apprise-api) server holds the destinations in a
stored configuration under a key; vmsnotify only names the key, so none of those addresses
or secrets sit on the VMS system. Store them once, on the Apprise server:

```sh
curl -X POST http://apprise.example.com:8000/add/openvms \
  -d 'urls=mailtos://user:password@mail.example.com?to=ops@example.com'
```

Apprise URLs for some common destinations (its
[wiki](https://github.com/caronc/apprise/wiki) has the rest):

| Destination | Apprise URL |
|---|---|
| Mail (SMTP over TLS) | `mailtos://user:password@mail.example.com?to=ops@example.com` |
| Matrix | `matrixs://user:password@matrix.example.com/#ops` |
| Microsoft Teams | `msteams://...`, made from the channel's webhook URL as the wiki describes |
| Pushover | `pover://USER_KEY@APP_TOKEN` |
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Discord | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| Slack | `slack://TOKEN_A/TOKEN_B/TOKEN_C/#ops` |

Then:

```
[endpoint everyone]
type = apprise
url  = https://apprise.example.com
key  = openvms
# tag  = critical          # only the stored URLs with this tag
# user = vmsnotify         # if the Apprise server is behind basic authentication
# password = ...
```

Apprise gets the title, the body, and `info`, `warning` or `failure` as the type. The
servers Apprise forwards to (Pushover, Telegram and so on) are outside services; the VMS
system talks only to your Apprise server.

### Webhooks: Home Assistant, Node-RED, n8n

A webhook gets one JSON object per notification: `kind` (`event`, `summary` or `notice`),
`node`, `title`, `message`, `priority`, `rule`, and the decoded `record` with its source,
time, severity, body and attributes (`openvms.audit.username`,
`openvms.audit.remote_nodename` and so on), so an automation can act on any field. A
`token` is sent as `Authorization: Bearer ...`; `user` and `password` as basic
authentication.

Home Assistant: an automation with a **Webhook** trigger (method POST); the data is
`trigger.json`.

```
[endpoint homeassistant]
type = webhook
url  = http://homeassistant.local:8123/api/webhook/vmsnotify-7f3a9c
```

Node-RED: an **http in** node for POST `/openvms`, followed by an **http response** node.

```
[endpoint nodered]
type = webhook
url  = http://nodered.example.com:1880/openvms
```

n8n: a **Webhook** node, method POST, path `openvms`, with Header Auth on the name
`Authorization` and the value `Bearer` followed by the token.

```
[endpoint n8n]
type       = webhook
url        = https://n8n.example.com/webhook/openvms
token_file = VMSNOTIFY$ROOT:[CONF]N8N.TOKEN
```

### Rules

Your rules come before the built-in ones, and the first that matches decides. Some common
ones:

```
# Before the first [section]: the built-in rules' notifications go to gotify only,
# so the rules below decide what else reaches the phone.
rules.defaults.to = gotify

# A monitoring host that logs in and out all day: its login failures are noise.
[rule monitoring-host]
source = audit
types  = LOGFAIL
remote = *192.168.0.131
action = ignore

# Shadow set trouble: high priority, to Gotify and the phone.
[rule shadow-sets]
source   = opcom
text     = *SHADOW*
priority = high
to       = gotify, phone

# Break-ins to every endpoint, every one of them, not summarised.
[rule breakins]
source   = audit
types    = BREAKIN
priority = urgent
throttle = 0
```

Repeats of a rule's event for the same person and place within 300 s are counted and sent
as one summary; `throttle` changes the window for one rule, and 0 sends every one.

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
`kit/make_kit.com` drift. The kit has been installed, run, started and stopped by its
startup and shutdown procedures, removed and reinstalled on all three systems, and upgraded
on x86 (`docs/findings.md`, "The kit").

## Licence

MIT; see [LICENSE](LICENSE). Parts come from [vmsotel](https://github.com/issinoho/vmsotel),
by the same author under the same licence.
