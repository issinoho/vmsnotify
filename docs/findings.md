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
users and remote nodes differ, so the throttle sees two groups and the user gets two
notifications for one attempt. Not yet dealt with.

The probe's driver procedures name `USER$ROOT:[IAIN.VMSNOTIFY]`; for the Alpha they were
edited on the way up. They should take their directory from where they are.
