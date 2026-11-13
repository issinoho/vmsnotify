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
