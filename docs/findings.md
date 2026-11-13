# Probe findings

One row per question per machine, with the output that settles it. A question is
answered for a machine only when that machine has a row. vmsotel's `docs/findings.md`
holds the evidence for what was copied from it (the readers, the parsers, the transport).

Machines: **x86** = X86VMS, OpenVMS E9.2-4 (a QEMU guest), VSI C V7.7. IA64 and Alpha: not
yet run.

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
