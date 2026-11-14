# Probe findings

One row per question per machine, with the output that settles it. A question is
answered for a machine only when that machine has a row. vmsotel's `docs/findings.md`
holds the evidence for what was copied from it (the readers, the parsers, the transport).

Machines: **x86** = X86VMS, OpenVMS E9.2-4 (a QEMU guest), VSI C V7.7. **IA64** = MYI64,
an rx2660, V8.4-2L3, VSI C V7.4-001 (its rows are in "IA64", below). **Alpha** = AXPBOX, an
AlphaServer DS10L under Charon-AXP, V8.4-2L2, VSI C V7.4-002 ("Alpha", below).

## The read position across processes (design D8)

`probes/probe_position.c`, built by `build_probes.com`, run as batch jobs with
`tools/vms.sh x86 batch` on **2026-11-13** as IAIN (READALL among its privileges). It opens
a file as the log reader does (FAC=GET, SHR=GET|PUT|UPD, ROP=NLK|RRL), saves the resultant
file spec with its version, the FID, and the RFA, length and first bytes of a record; a
later process reopens and continues from there. Test files in the work directory; the
real logs were only read.

| # | Question | x86 | Evidence / notes |
| --- | --- | --- | --- |
| P1 | The probe builds; no LINK warnings | yes | `built:  probe_position`, no compiler message |
| P2 | A record's RFA, saved by one process, finds it in another | **yes** | Saved in batch job A: `saved record 8 of 10: rfa=00010000009A len=20`, FID `(56753,216,0)`. In a different batch job (entry 436): `PASS open status=00010001 resultant USER$ROOT:[iain.vmsnotify]TEST.LOG;1`, `PASS fid matches the saved one`, `PASS get by RFA status=00010001, 20 bytes: RECORD 00008 created`, `PASS record matches the saved length and first 20 bytes`. The same from a SPAWN/WAIT subprocess |
| P3 | Records written after the save are read from there | yes | 5 records appended between save and resume: `first record after it: RECORD 00009 created`, `7 records followed` (2 + 5), `ended with status=0001827A (RMS$_EOF)` |
| P4 | A new version of the file is noticed | yes, by its FID | With `TEST.LOG;2` created: opening without a version gave `resultant …TEST.LOG;2`, `opened fid (56862,122,0)`, `DETECTED fid differs: this is a DIFFERENT FILE (newer version)`. The saved `;1`, still there, resumed with every PASS |
| P5 | The saved version is gone | a clean failure | `FAIL open status=00018292 (RMS$_FNF)` |
| P6 | The same on the real operator log | yes | `resultant: SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251`, `fid: (18146,54,256)`, `read 954 records`; `saved record 952 of 954: rfa=00340000016E len=0`; resume: `PASS open`, `PASS fid matches`, `PASS get by RFA status=00010001, 0 bytes`, `2 records followed` |
| P7 | The same on the real audit journal | yes | `resultant: SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;6`, `fid: (18147,66,256)`, `read 6923 records`; `saved record 6921 of 6923: rfa=0D440000002A len=295`; resume: every PASS, `295 bytes`, `record matches the saved length and first 48 bytes`, `2 records followed` |

What the reader takes from this:

- **Keep all three FID words.** The third is `nam$b_fid_rvn | nam$b_fid_nmx << 8`, and it is
  256 on the system logs (file numbers past 16 bits), 0 on the small test files.
- **The resultant spec is a logical form** (`SYS$SYSROOT:[SYSMGR]…`), which reopens; the FID
  is what proves it is the same file.
- **A saved record can be empty.** OPERATOR.LOG has zero-length records (P6's was one), so
  the saved bytes may be nothing: compare RFA, length and bytes, and accept an empty head.
- **A gone file is RMS$_FNF:** start at the end and say what was skipped.

Not tested: REPLY/LOG and SET AUDIT/SERVER=NEW_LOG themselves (P4 stands in for them, with
a new version made by hand; they are system-wide and need the user's say-so); a file
rewritten in place under the same FID (the length and bytes comparison is there for that);
the real logs growing between save and resume (they did not, in this run).

One thing about the machine: its batch queues run one job at a time, so a batch job that
submits another and waits for it waits forever. The cross-job check ran as three jobs in
turn.

## The agent on VMS

`build_vms.com`, as batch jobs, 2026-11-13.

| # | Question | x86 | Evidence / notes |
| --- | --- | --- | --- |
| B1 | `build_vms` builds both images; no warnings | yes | `vmsnotify build, X86VMS, OpenVMS E9.2-4 x86_64`, `OpenSSL: SYS$LIBRARY:SSL3$LIBSSL_SHR32, SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32, headers SSL3$INCLUDE`, `built: vmsnotify.exe vmsnotify_tls.exe`, no compiler or linker message, first time; no source needed changing for VSI C. `--version`: `vmsnotify 0.1.0` from both. CLEAN and a rebuild gave the same |
| B2 | The node name from `SYI$_NODENAME` | yes | `vmsnotify 0.1.0 starting on X86VMS` |
| B3 | The agent opens the real logs and starts at their end | yes | `build_vms DRYRUN`: `logs: starting at the end of SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251 (954 records, 0 s); starting at the end of SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;6 (6923 records, 1 s)` -- the record counts the position probe read (P6, P7); `done: 2 cycles, 0 records, … 2 notices; 0 sent`, exit `%X00000001` |
| B4 | `--test` reaches every endpoint type | yes (a stand-in) | To `tools/fake_endpoints.py --bind 192.168.0.131 --serve 18555`, which checks each request as its server would: `ok    g (gotify): HTTP 200`, `ok    a (apprise): HTTP 200`, `ok    n (ntfy): HTTP 200`, `ok    w (webhook): HTTP 200`, `ok: 0 of 4 endpoints failed`; title `X86VMS: vmsnotify test`, `X-Gotify-Key` and `User-Agent: vmsnotify/0.1.0` as sent |
| B5 | A run sends its notices and saves its position | yes | `--cycles 6`: `notice [low] to g, a, n, w: X86VMS: vmsnotify started`, `… stopped`, `8 sent, 0 failed attempts, 0 dropped, 0 unsent`. The position file: `opcom = rms1 SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251 18146,54,256 R 52,0,426 18 4c6f67…` and `audit = rms1 SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;6 18147,66,256 R 3397,0,122 1401 0b00…` -- the FIDs the probe saw (P6, P7) |
| B6 | The agent resumes from its saved position | yes | The next run: `logs: resuming in SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251 at the saved position (0 records written while stopped); resuming in SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;6 at the saved position (0 records written while stopped)`. With nothing written in between; records waiting at a resume have not been seen on VMS |
| B7 | A real login failure arrives, and how soon | **yes, in 2 to 5 s** | Three wrong-password SSH logins as IAIN from 192.168.0.131 at 18:42:37, :49 and 18:43:01, with a rule matching everything: `18:42:41Z event all [normal] to g, a, n, w: X86VMS: Login failure: remote user IAIN from 192.168.0.131 on FTA9501:`, then `18:42:51Z … FTA9502:`, `18:43:06Z … FTA9503:`; `3 records, … 3 events, … 20 sent, 0 failed attempts`. The webhook's record: `"openvms.audit.type":"LOGFAIL"`, `"openvms.audit.username":"IAIN"`, `"openvms.audit.remote_nodename":"192.168.0.131"`, `"openvms.audit.terminal":"FTA9501:"`, `"openvms.audit.status":"%X00D380FC"`, time `2026-11-13 18:42:39 UTC`. The two clocks agree to the second |
| B8 | The default rules, the throttle and a break-in | yes | Three more, `rules.defaults.throttle = 30`: `18:45:10Z event login-failure [high] … on FTA9505:`; the second counted; the third VMS itself recorded as a break-in (the sixth failure from that source): `18:45:30Z event breakin [urgent] to g, a, n, w: X86VMS: Break-in attempt: remote user IAIN from 192.168.0.131 on FTA9507:` (ntfy `Priority: 5`); `18:45:40Z summary login-failure [high] …: X86VMS: 1 more: Login failure: …`, 30 s after the first. `3 records, 0 ignored, 2 events, 1 throttled, 1 summaries`. SHOW INTRUSION afterwards: `NETWORK INTRUDER 6 … 192.168.0.131::IAIN`, expiring five minutes on; key logins from there still worked |

Of the 61 requests the stand-in logged, 60 were valid (the other was a curl to see that
the port answered).

Not yet on x86: the real Gotify, Apprise API and ntfy servers; TLS; an operator-log
record through the rules (none was written during the runs); records waiting at a resume;
`descrip.mms`; running detached; the kit.

## IA64

MYI64, 2026-11-13, as batch jobs with `tools/vms.sh ia64 batch`, as IAIN; the same
procedures as x86, the same questions. **No source change was needed.**

| # | IA64 | Evidence / notes |
| --- | --- | --- |
| P1 | yes | `vmsnotify probes, MYI64, OpenVMS V8.4-2L3 IA64`, `built:  probe_position`, no message |
| P2, P3 | yes | Saved in one batch job (`saved record 8 of 10: rfa=00010000009A len=20`, FID `(10485,7,256)`), resumed in the next (entry 984): `PASS open`, `PASS fid matches the saved one`, `PASS get by RFA status=00010001, 20 bytes: RECORD 00008 created`, `PASS record matches the saved length and first 20 bytes`, `7 records followed`. The same from a subprocess |
| P4 | yes | `PASS open … TEST.LOG;2`, `opened fid (10580,5,256)`, `DETECTED fid differs: this is a DIFFERENT FILE (newer version)` |
| P5 | a clean failure | `FAIL open status=00018292 (RMS$_FNF)` |
| P6 | yes | `SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;23`, fid `(58537,24,0)`, `read 452 records`, `saved record 450 of 452: rfa=001B0000015C len=0`; resume all PASS, `2 records followed` |
| P7 | yes | `SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;4`, fid `(58857,13,0)`, `read 19 records`, `saved record 17 of 19: rfa=00100000009E len=417`; resume all PASS |
| B1 | yes | `built: vmsnotify.exe vmsnotify_tls.exe`, no compiler or linker message from VSI C V7.4; `vmsnotify 0.1.0` from both |
| B2, B3 | yes | `starting on MYI64`; `logs: starting at the end of …OPERATOR.LOG;23 (452 records, 0 s); … SECURITY.AUDIT$JOURNAL;4 (19 records, 0 s)`, the probe's counts |
| B4 | yes (a stand-in) | `ok    g (gotify): HTTP 200`, `ok    a (apprise): HTTP 200`, `ok    n (ntfy): HTTP 200`, `ok    w (webhook): HTTP 200`, `ok: 0 of 4 endpoints failed` |
| B5 | yes | `8 sent, 0 failed attempts, 0 dropped, 0 unsent`; `opcom = rms1 SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;23 58537,24,0 R 27,0,408 18 4c6f67…`, `audit = rms1 SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL;4 58857,13,0 R 17,0,166 1401 0b00…` |
| B6 | yes | `logs: resuming in …OPERATOR.LOG;23 at the saved position (0 records written while stopped); resuming in …SECURITY.AUDIT$JOURNAL;4 at the saved position (0 records written while stopped)` |
| B7, B8 | yes, in 3 to 5 s; no break-in made | Two wrong-password SSH logins, default rules, throttle 30: attempt at 18:55:34, the record's time 18:55:36, `18:55:39Z event login-failure [high] to g, a, n, w: MYI64: Login failure: remote user IAIN from 192.168.0.131 on FTA86:`; the second counted, `18:56:09Z summary login-failure [high] … MYI64: 1 more: Login failure: …`; `2 records, 0 ignored, 1 events, 1 throttled, 1 summaries, … 16 sent, 0 failed attempts`. SHOW INTRUSION: `NETWORK SUSPECT 2 … 192.168.0.131::IAIN` |

Different from x86: the FID's third word is 0 on IA64's system logs and 256 on its test
file -- the reverse of x86 -- so it is a property of the file, not of system logs; all
three words are kept either way.

Not yet on IA64: as x86's list, and a break-in record (two failures make only a SUSPECT).

## The real servers

Gotify 3.1.1, the Apprise API (caronc/apprise 2.1.0) and ntfy v2.37.2, from
`tools/test-endpoints/compose.yaml`, on docker-nuc, 2026-11-13. The Apprise key `vms`
holds one URL, the Gotify application's. Plain HTTP on the LAN.

| # | Question | Linux | x86 | IA64 | Evidence / notes |
| --- | --- | --- | --- | --- | --- |
| R1 | `--test` is accepted by each real server | yes | yes | yes | (Alpha too: the same three `ok` lines, and `AXPBOX: vmsnotify test` read back from ntfy.) On each: `ok    gotify (gotify): HTTP 200`, `ok    apprise (apprise): HTTP 200`, `ok    ntfy (ntfy): HTTP 200`, `ok: 0 of 3 endpoints failed`, exit `%X00000001` on VMS. Read back from ntfy's topic: `THINKPAD-X280: vmsnotify test` (priority 3, tag `openvms`), `X86VMS: vmsnotify test`, `MYI64: vmsnotify test`. Gotify's own list was not read back (it needs a client token; the application's gives 401), so its messages and Apprise's forwarding are for the user's eyes |
| R2 | The token file on VMS | - | yes | yes | `gotify.token;1 … (RWED,RWED,,)` in the work directory; the agent read it (`token_file`) and nothing printed it |

Not yet: events (not only the test notice) to the real servers; TLS in front of any of
them.

## Alpha

AXPBOX, 2026-11-13, batch jobs with `tools/vms.sh alpha batch` in `DISK$WORK:[IAIN.VMSNOTIFY]`,
as IAIN, who has every privilege there by default. **No source change was needed.**

| # | Alpha | Evidence / notes |
| --- | --- | --- |
| P1 | yes | `vmsnotify probes, AXPBOX, OpenVMS V8.4-2L2 Alpha`, `built:  probe_position`, no message |
| P2, P3 | yes | Saved in one batch job (entry 531; FID `(2085,1,0)`), resumed in the next (532): `PASS open`, `PASS fid matches the saved one`, `PASS get by RFA … 20 bytes: RECORD 00008 created`, `PASS record matches the saved length and first 20 bytes`, `7 records followed` |
| P4, P5 | yes; a clean failure | `opened fid (2092,1,0)`, `DETECTED fid differs: this is a DIFFERENT FILE (newer version)`; `FAIL open status=00018292 (RMS$_FNF)` |
| P6, P7 | yes | `OPERATOR.LOG;156`, fid `(4711,8,0)`, `read 165 records`, `saved record 163 of 165: … len=0`, resume all PASS. `SECURITY.AUDIT$JOURNAL;11`, fid `(9078,6,0)`, `read 43 records`, `saved record 41 of 43: … len=1029`, resume all PASS |
| B1 | yes | `vmsnotify build, AXPBOX, OpenVMS V8.4-2L2 Alpha`, `built: vmsnotify.exe vmsnotify_tls.exe`, no message: the `/FLOAT=IEEE_FLOAT` branch's first run. Nothing in the agent uses floating point today |
| B2, B3 | yes | `starting on AXPBOX`; `starting at the end of …OPERATOR.LOG;156 (165 records, 0 s); … SECURITY.AUDIT$JOURNAL;11 (43 records, 0 s)` |
| B4–B6 | yes (a stand-in) | `ok: 0 of 4 endpoints failed`; `8 sent, 0 failed attempts`; `opcom = rms1 SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;156 4711,8,0 R 12,0,282 18 …`, `audit = rms1 …SECURITY.AUDIT$JOURNAL;11 9078,6,0 R 48,0,364 98 …`; then `resuming in … at the saved position (0 records written while stopped)` for both |
| B7, B8 | yes, in about 1 s; **two records per failed login** | Two wrong-password SSH logins at 19:04:21 and :31: `19:04:24Z event login-failure [high] to g, a, n, w: AXPBOX: Login failure: remote user iain from 192.168.0.131`, and a second event the same second; summaries `1 more: Login failure: …` at 19:04:54; `4 records, 0 ignored, 2 events, 2 throttled, 2 summaries`. SHOW INTRUSION: two SUSPECT entries, `192.168.0.131::iain` and `SSH_PASSWORD:192.168.0.131::IAIN` |
| B9 | Without READALL: says so, sends a notice, does not crash | `set process/privileges=(noall,netmbx,tmpmbx)`: `logs: cannot read SYS$MANAGER:OPERATOR.LOG: %RMS-E-FNF, file not found; cannot read SYS$MANAGER:SECURITY.AUDIT$JOURNAL: %RMS-E-PRV, insufficient privilege or file protection violation`, `notice [high] to g, a, n, w: AXPBOX: vmsnotify cannot read a log`, `done: 2 cycles … 3 notices; 12 sent`, exit `%X00000001`. With READALL added it read both. (Alpha only; not run on x86 or IA64) |

Different on Alpha: **one failed SSH password login makes two LOGFAIL records** -- one from
`SSH$SSHD-SESSION.EXE` (user IAIN, remote user `iain`, remote node `192.168.0.131`) and one
as username `SSH$SSH` (remote user `IAIN`, remote node `SSH_PASSWORD:192.168.0.131`, status
`%X00D3803C`) -- neither with a terminal. x86 and IA64 make one, with a terminal. Their
users and remote nodes differ, so the throttle saw two groups and the user got two
notifications for one attempt. **Now handled in code** (`docs/design.md`, "Throttle"): the
throttle key is the upper-cased remote username (else username) from the remote node without
a service prefix, so both records are `IAIN from 192.168.0.131`, and a record with the same
rule and key within 2 s of one just admitted is dropped silently as its twin. Tested on
Linux (`tests/test_rules.c`, the Alpha pair; `tools/agent_test.py`, the same pair through
the fake log source). **Not yet re-run on the Alpha**: one wrong password there should now
give one event, no "1 more", and `1 duplicates` in the final line.

The probe's driver procedures (`probes/position_test.com`, `position_batch.com`) used to name
`USER$ROOT:[IAIN.VMSNOTIFY]` and were edited on the way up for the Alpha. They now take the
work directory from their own location (the directory above `probes/`); not yet run on VMS
since that change.

| # | Alpha | Evidence / notes |
| --- | --- | --- |
| B10 | One failed login is one notification, after 18e8a8b | Rebuilt on AXPBOX (`built: vmsnotify.exe vmsnotify_tls.exe`), to the real Gotify and ntfy, default rules, throttle 30. Two wrong-password SSH logins at 20:07:31 and 20:07:42: `20:07:32Z event login-failure [high] to gotify, ntfy: AXPBOX: Login failure: remote user iain from 192.168.0.131`, `20:08:02Z summary login-failure [high] …: AXPBOX: 1 more: Login failure: …`, `done: 48 cycles, 4 records, 0 ignored, 1 events, 1 throttled, 1 summaries, 2 duplicates, 2 notices; 8 sent, 0 failed attempts, 0 dropped, 0 unsent`. Read back from ntfy: the event at 20:07:33 (priority 4) and the summary at 20:08:03. So this is also the first real event at the real servers. The first submit of this job never ran (the node's SSH); the second did |

## After 18e8a8b (the throttle's key and twins)

| # | x86 | IA64 | Evidence / notes |
| --- | --- | --- | --- |
| A1 | yes | yes | Rebuilt with the change: `built: vmsnotify.exe vmsnotify_tls.exe`, no message; `--test` to the real servers: `ok    gotify (gotify): HTTP 200`, `ok    apprise (apprise): HTTP 200`, `ok    ntfy (ntfy): HTTP 200`, `ok: 0 of 3 endpoints failed` |
| A2 | yes | yes | The reworked `probes/position_test.com`, called as `@[.probes]position_test A` from the work directory, found its own way: `created TEST.LOG: 10 records … resultant USER$ROOT:[iain.vmsnotify]TEST.LOG;1`, `saved record 8 of 10: rfa=00010000009A len=20`, `PASS save wrote TEST.STATE`. Stage A only; stage B and the batch resume not re-run |

The twin rule itself is shown on the Alpha (B10), the one machine that writes twins.
IA64's first submit of this job never ran; the second was entry 11 on SYS$BATCH, where
the afternoon's were in the 980s, so IA64 had been restarted in between.

## TLS to the real servers

The `tls` service of `tools/test-endpoints/compose.yaml` on docker-nuc: nginx in front of
Gotify (18443), the Apprise API (18444) and ntfy (18445), with a self-signed certificate
`CN=vmsnotify-test-endpoints`, `IP Address:192.168.0.218`, valid to 15 Feb 2029, SHA-256
`22:1F:87:7D:…:FB:61:15`, fetched with `openssl s_client` and given as `cafile`
(`TEST-ENDPOINTS.CRT` in each work directory). 2026-11-13.

| # | Question | Linux | x86 | IA64 | Alpha | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | `--test` over verified TLS to each real server | yes | yes | yes | yes | On each, `VMSNOTIFY_TLS`: `ok    gotify (gotify): HTTP 200, TLSv1.3 TLS_AES_256_GCM_SHA384`, the same for apprise and ntfy, `ok: 0 of 3 endpoints failed`, exit `%X00000001` on VMS |

Refusal with the wrong certificate, and the plain image refusing https, are tested on Linux
(`tools/agent_test.py`) and against the stand-in from VMS (the stand-in TLS run).

## TLS refusals (the stand-in)

`tools/fake_endpoints.py --bind 192.168.0.131 --serve 18556 … TLSDIR` on the laptop, its
certificate (now naming `IP:192.168.0.131`) as `STANDIN.CRT`; four endpoints, one of each
type; one batch job per machine, `VMSNOTIFY_TLS` unless said. 2026-11-13.

| # | Question | x86 | IA64 | Alpha | Evidence |
| --- | --- | --- | --- | --- | --- |
| T2 | Verified against the right certificate | yes | yes | yes | `ok    webhook (webhook): HTTP 200, TLSv1.3 TLS_AES_256_GCM_SHA384` and the same for the other three, `ok: 0 of 4 endpoints failed`. OpenSSL `3.0.21 9 Jun 2026` on x86, `3.0.22 25 Aug 2026` on IA64 and the Alpha |
| T3 | A wrong certificate as cafile is refused | yes | yes | yes | `FAIL  gotify (gotify): TLS certificate: self-signed certificate` and the same for the other three, `FAILED: 4 of 4 endpoints failed`; nothing reached the stand-in |
| T4 | Without cafile, a self-signed server is refused | yes | yes | yes | The same four refusals against the system's CAs; nothing reached the stand-in |
| T5 | The plain image refuses https | yes | yes | yes | `not starting: endpoint gotify is https, but this image was built without TLS`, for `--test` and for a run |
| T6 | A run delivers its notices over TLS | yes | yes | yes | `--cycles 4`: `done: 4 cycles, … 2 notices; 8 sent, 0 failed attempts, 0 dropped, 0 unsent`; x86: `endpoint gotify: TLS through OpenSSL 3.0.21 9 Jun 2026, CA USER$ROOT:[IAIN.VMSNOTIFY]STANDIN.CRT` |

The stand-in logged 36 requests, all valid, 12 from each machine (one test and two notices
per endpoint): none from the refused cases.

Not tested: a certificate with the right root but the wrong address; TLS 1.2; an expired
certificate; whether the VMS machines' system CA stores trust a public CA.

## The operator log (OPCOM)

One plain `REQUEST "vmsnotify OPCOM test <NODE> M<hhmmss>"` per machine, approved by the
user, sent from a batch job, 2026-11-13 23:58 UTC.

| # | Question | x86 | IA64 | Alpha | Evidence / notes |
| --- | --- | --- | --- | --- | --- |
| O1 | The REQUEST reaches OPERATOR.LOG, and how soon | at once | at once | **at once** | `SHOW TIME` 23:58:23, 23:58:20, 23:58:26; headers `OPCOM  13-NOV-2026 23:58:23.52`, `… 23:58:20.99`, `… 23:58:26.08`. On the Alpha, not the 10–11 minutes vmsotel A19 saw; why it differs was not looked into |
| O2 | How a plain REQUEST is written | as a **message**, not a request | the same | the same | `Message from user IAIN on X86VMS`, `BATCH_473, vmsnotify OPCOM test X86VMS M235823`. Only `REQUEST/REPLY` gives `Request N, from user …` |
| O3 | The default rules and a plain REQUEST | **ignored** | ignored | ignored | The agent, resumed from a position saved before the REQUEST, read it: `resuming in SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251 at the saved position (2 records written while stopped)`, `done: 180 cycles, 2 records, 2 ignored, 0 events` (x86; IA64 and the Alpha `1 records, 1 ignored`). `opcom-request` matches only numbered requests (`openvms.opcom.request`), and a plain message with no condition code matches nothing else |
| O4 | An operator message through a rule to the real servers | yes | - | - | x86, resumed again with `[rule opcom-marker] source = opcom, text = *vmsnotify OPCOM test*`: `event opcom-marker [normal] to gotify, apprise, ntfy: X86VMS: BATCH_473, vmsnotify OPCOM test X86VMS M235823`, `9 sent, 0 failed attempts`; ntfy got priority 3, title `X86VMS: BATCH_473, vmsnotify OPCOM test X86VMS M235823`, body `Message from user IAIN on X86VMS`, the text, `Time: 2026-11-13 23:58:23 UTC`, `Rule: opcom-marker` |

| O5 | A plain REQUEST under the default rules, with `opcom-message` | yes | - | - | After the change below, rebuilt on x86 and resumed from the same saved position with no rule of its own: `event opcom-message [normal] to gotify, apprise, ntfy: X86VMS: BATCH_473, vmsnotify OPCOM test X86VMS M235823`, `2 records, 1 ignored, 1 events … 9 sent, 0 failed attempts`; ntfy: priority 3, the same title |

Decided with the user after O3: a new default, `opcom-message`, sends OPCOM messages from any
user but SYSTEM at normal priority (a person's message to the operators; SYSTEM's are
routine), with a new rule setting, `not_user`, to say so.

The live delay from OPERATOR.LOG to a notification was not measured: the first run's agents
did not start (a mistake in the test procedure), so each was resumed from an earlier saved
position afterwards. A numbered request (`REQUEST/REPLY`) was not tried: it waits for a
REPLY.

## Running detached

`VMSNOTIFY_START.COM` (`RUN/DETACHED SYS$SYSTEM:LOGINOUT`, process VMSNOTIFY, privileges
`NOSAME,NETMBX,TMPMBX,READALL`), `VMSNOTIFY_RUN.COM` and `VMSNOTIFY_STOP.COM`, source-tree
layout, as IAIN. `VMSNOTIFY.CONF` was the T1 configuration (the real Gotify, Apprise API and
ntfy over verified TLS) with `interval = 10`. x86 ran 10 minutes alone (00:46–00:56 UTC,
2026-11-14), then all three ran an hour together (00:57–01:58). At 01:07:00 two
wrong-password SSH logins as IAIN were made to each machine, 10 s apart.

| # | Question | x86 | IA64 | Alpha | Evidence / notes |
| --- | --- | --- | --- | --- | --- |
| D1 | It runs detached with exactly NETMBX, TMPMBX and READALL | yes | yes | yes | `VMSNOTIFY_RUN.LOG`, `SHOW PROCESS/PRIVILEGES`: authorized and process privileges NETMBX, READALL, TMPMBX. Start line `vmsnotify 0.1.0 starting on X86VMS: every 10 s, 9 rules, queue 32`, then `notice [low] to gotify, apprise, ntfy: X86VMS: vmsnotify started` |
| D2 | Live login failures in a detached run, throttled | yes | yes | yes | `01:07:09Z event login-failure [high] … X86VMS: Login failure: remote user IAIN from 192.168.0.131 on FTA9535:`, `01:12:09Z summary … 1 more`; IA64 01:07:07 and 01:12:07, on FTA107; Alpha 01:07:09 and 01:12:09, `remote user iain`, no terminal. ntfy received exactly 12 messages from the three: 3 started, 3 login failures and 3 summaries at priority 4, 3 stopped |
| D3 | `VMSNOTIFY_STOP` stops it cleanly | yes | yes | yes | `vmsnotify: acknowledged; waiting for it to finish sending`, then `vmsnotify_run: agent exited, status %X00000001`. x86 `stopped: 366 cycles, 3 records, 1 ignored, 1 events, 1 throttled, 1 summaries, 0 duplicates, 2 notices; 12 sent, 0 failed attempts, 0 dropped, 0 unsent`; IA64 the same; Alpha `367 cycles, 5 records … 2 duplicates`, the rest the same (its two records per failed login, B10) |
| D4 | The position file stays small | **no**, fixed | no | no | Each save wrote a new version (rename does not replace on VMS): `VMSNOTIFY.POS` reached 4 versions in the hour. The agent now deletes the version before each one it writes. x86, two runs against a deliberately stale file: `;1` → `;2` written, `;1` gone; then (stale `;3` written by hand) `;4` written, `;3` gone |

CPU for the hour: x86 25.33 s, IA64 0.70 s, Alpha 8.47 s; connect time 1:01 on each. x86's
rose evenly (about 5 s at 10 minutes); why it costs so much more there (a QEMU guest) was
not looked into.

`SHOW INTRUSION` at the stop, 50 minutes after the logins, found no records on any machine;
whether the two failures made SUSPECT entries that had since expired was not checked.

Not tested: the kit's layout and account, a start from SYSTARTUP, a run longer than an
hour, and D4's fix on IA64 and the Alpha.

## The kit

| # | Question | x86 | IA64 | Alpha | Evidence / notes |
| --- | --- | --- | --- | --- | --- |
| K1 | Build, install, configure, run as its own account | **yes** | - | - | 2026-11-14, as IAIN with every privilege, approved by the user. `build_vms`: `built: vmsnotify.exe vmsnotify_tls.exe vmsnotify_launch.exe`. MAKE_KIT: `ISSINOHO-X86VMS-VMSNOTIFY-V0001-0-1.PCSI`, 832 blocks, 13 files. `PRODUCT INSTALL … /OPTIONS=NOCONFIRM`: `not signed`, installed to `DISK$X86SYS:[VMS$COMMON.]`, the POST_INSTALL text in full; `VMSNOTIFY$ROOT` = `X86VMS$DKA0:[SYS0.SYSCOMMON.VMSNOTIFY.]`. `VMSNOTIFY$CONFIGURE VMSNOTIFY [351,1] NO` ([351] was free; [350] is vmsotel's): `user record successfully added`; AUTHORIZE: owner `vmsnotify agent`, `DisCtlY LockPwd`, every login class `No access`, `Pwdchange: (pre-expired)`, authorized and default `NETMBX READALL TMPMBX`; CONF, DATA and LOG `[VMSNOTIFY] (RWE,RWE,,)`, BIN, COM, DOC `[SYSTEM] (RWE,RWE,RE,RE)`. The T1 settings, the Gotify token and the CA certificate copied to [CONF], owned by VMSNOTIFY `(RWED,RWED,,)`. `VMSNOTIFY_START`: `vmsnotify_launch: process 0002C6D5 started as VMSNOTIFY`; from IAIN, `user VMSNOTIFY uic [VMSNOTIFY]`, `authpriv` and `curpriv TMPMBX,NETMBX,READALL`; VMSNOTIFY_RUN.LOG: process rights `VMSNOTIFY` only. Position `…[VMSNOTIFY.DATA]VMSNOTIFY.POS`. One wrong-password SSH login at 07:35:13: `07:35:24Z event login-failure [high] … X86VMS: Login failure: remote user IAIN from 192.168.0.131 on FTA9562:`; `VMSNOTIFY_STOP` (as IAIN): `acknowledged`, `stopped: 14 cycles, 1 records, 0 ignored, 1 events … 2 notices; 9 sent, 0 failed attempts, 0 dropped, 0 unsent`, `agent exited, status %X00000001`. ntfy: `07:33:45 started`, `07:35:25` the login failure at priority 4, `07:36:00 stopped`. Only `VMSNOTIFY.POS;2` left in [DATA]: D4's fix, in the kit |

Files the agent makes in [DATA] and [LOG] get the account's default protection,
`(RWED,RWED,RE,)`; their directories give group and world nothing, so that read access cannot
be used.

Not yet run: start and stop by VMSNOTIFY$STARTUP and $SHUTDOWN, an upgrade, PRODUCT REMOVE;
IA64 and the Alpha.
