# Running vmsnotify

The operator's page: install, configure, tokens, start, stop, upgrade
and remove. vmsnotify reads the operator log and the security audit
journal and sends what matters to Gotify, an Apprise API server, ntfy or
a webhook. It needs NETMBX, TMPMBX and READALL, and no more. The
settings are explained in `vmsnotify.conf.example`
(`VMSNOTIFY.CONF_EXAMPLE` in the kit); the design is in `docs/design.md`.

## Install

Two ways. **From the PCSI kit** (`ISSINOHO-<base>-VMSNOTIFY-...PCSI`;
x86-64, Integrity and Alpha, each needing VSI's SSL3 kit), the agent
runs as an account of its own, never as SYSTEM:

```dcl
$ product install vmsnotify /source=dev:[dir]
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE
```

`VMSNOTIFY$ROOT` is defined by the installation, and again at every
boot by `SYS$STARTUP:VMSNOTIFY$STARTUP.COM`. The kit is built from a
source tree by `@[.vmsnotify.kit]MAKE_KIT` after `build_vms`, into
`[.vmsnotify.KIT_<arch>]`.

The tree it makes:

| directory | holds | owner and access |
| --- | --- | --- |
| `[BIN]` | the three images | readable by all |
| `[COM]` | the procedures | readable by all |
| `[DOC]` | README.VMS, this page, LICENSE | readable by all |
| `[CONF]` | `VMSNOTIFY.CONF`, token files, certificates | the account; no group or world access |
| `[DATA]` | `VMSNOTIFY.POS`, the read position | the account; no group or world access |
| `[LOG]` | `VMSNOTIFY.LOG`, `VMSNOTIFY_RUN.LOG`, `VMSNOTIFY.STOP` | the account; no group or world access |

**From a source tree**, which runs as whoever starts it, with
`VMSNOTIFY.CONF`, the logs and the position beside the procedures:
`@[.vmsnotify]build_vms`, then `@[.vmsnotify]VMSNOTIFY_START`
(`README.md`).

## Configure

`@VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE`, once, as SYSTEM. It asks for
the account (default `VMSNOTIFY`) and, if the account is new, its UIC: a
group of its own above MAXSYSGROUP, for example `[360,1]`. It creates
the account with no login of any kind, NETMBX, TMPMBX and READALL, a
random password nobody knows, and the quotas the agent runs with; it
changes an existing account only if it created it (the owner field says
`vmsnotify agent`) and refuses a system-group UIC. It creates
`VMSNOTIFY$ROOT:[CONF]VMSNOTIFY.CONF` from the example if there is none,
sets the protections above, writes `SYS$MANAGER:VMSNOTIFY$CONFIG.COM`
(the account, and whether to start at boot) and defines the system
logical `VMSNOTIFY$USER`. Run it again whenever you want to change the
account's name or the boot setting.

Then edit `VMSNOTIFY.CONF`: set each `[endpoint NAME]`'s `url` and the
rules. Check it without sending anything:

```dcl
$ VMSNOTIFY := $VMSNOTIFY$ROOT:[BIN]VMSNOTIFY_TLS.EXE
$ VMSNOTIFY "VMSNOTIFY$ROOT:[CONF]VMSNOTIFY.CONF" "--dry-run" "--cycles" "2"
$ VMSNOTIFY "VMSNOTIFY$ROOT:[CONF]VMSNOTIFY.CONF" "--test"
```

The first prints what it would send, the second sends one notice to
every endpoint. Quote the options: DCL lowercases what it is not told to
keep.

### Tokens

Never write a token in `VMSNOTIFY.CONF`. Put each in a file of its own
in `[CONF]` and name it with `token_file`:

```text
[endpoint home]
type       = gotify
url        = https://gotify.example.org
token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
```

The file holds the token alone. A file you create there is yours, not
the account's, so hand it over and close it to everyone else:

```dcl
$ SET FILE/OWNER=VMSNOTIFY VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
$ SET FILE/PROTECTION=(S:RWED,O:RWED,G,W) VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
```

(Substitute the account's name if you chose another.) The agent never
writes a token, or a header that carries one, to its log. A certificate
for `cafile` goes in `[CONF]` too; it is not secret, but the account has
to read it. TLS is always verified.

## Start and stop

As SYSTEM (both need IMPERSONATE and WORLD):

```dcl
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_START
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP
```

`VMSNOTIFY_START` starts the process `VMSNOTIFY` as the account, by
persona (`VMSNOTIFY_LAUNCH.EXE`), and checks that it is still there three
seconds later. `VMSNOTIFY_STOP` creates `[LOG]VMSNOTIFY.STOP`, which the
agent looks for once a second; it deletes the file, sends the summaries
of its open windows and a "stopped" notice, writes its last line to
`VMSNOTIFY.LOG` and exits. Do not use `STOP/IDENTIFICATION`: the agent
would lose what it has queued without saying so. The agent does not
restart itself; `VMSNOTIFY.LOG` says why it stopped.

When it does not start, `[LOG]VMSNOTIFY_RUN.LOG` (DCL's, before the
agent) says why. When it runs but does not notify, `[LOG]VMSNOTIFY.LOG`
has one line per event, and `--dry-run` shows what the rules decide.

### At boot and shutdown

Add to `SYS$MANAGER:SYSTARTUP_VMS.COM`, after TCP/IP is up:

```dcl
$ @SYS$STARTUP:VMSNOTIFY$STARTUP.COM
```

and to `SYS$MANAGER:SYSHUTDWN.COM`:

```dcl
$ @SYS$STARTUP:VMSNOTIFY$SHUTDOWN.COM
```

The first defines `VMSNOTIFY$ROOT` and `VMSNOTIFY$USER` and, if
`VMSNOTIFY$CONFIGURE` was told to start at boot, starts the agent. The
second stops it as `VMSNOTIFY_STOP` does, so that it sends what it has
queued and logs what it could not.

## Where it resumes

`[DATA]VMSNOTIFY.POS` records how far each log has been read. After a
restart, events written while the agent was stopped are sent if they are
no older than `catchup.max_age` and no more than `catchup.max_records`;
otherwise it starts at the end and says what it skipped. Deleting the
file does the same as a first start.

## Upgrade

Install the new kit over the old one:

```dcl
$ product install vmsnotify /source=dev:[dir]
```

PCSI replaces the images, procedures and documents. The configuration,
the tokens, the position, the logs, the site settings and the account
are not part of the kit and are left alone. Stop the agent first
(`VMSNOTIFY_STOP`) and start it again afterwards.

## Remove

```dcl
$ product remove vmsnotify
```

stops the agent and deassigns `VMSNOTIFY$ROOT` and `VMSNOTIFY$USER`.
The configuration, tokens, position, logs, `SYS$MANAGER:VMSNOTIFY$CONFIG.COM`
and the account stay, so that a reinstall carries on where it left off.
Remove the lines from `SYSTARTUP_VMS.COM` and `SYSHUTDWN.COM` yourself,
and the account with AUTHORIZE if you want it gone.
