$! vmsnotify_stop.com -- ask the agent to stop, and wait for it
$!
$!     @dev:[dir.VMSNOTIFY]VMSNOTIFY_STOP      the source tree
$!     @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP     installed from the kit; at
$!                                             shutdown, VMSNOTIFY$SHUTDOWN
$!
$! Creates VMSNOTIFY.STOP (beside this file, or in the kit's [LOG]),
$! which the agent looks for
$! once a second. It deletes the file -- the acknowledgement this waits
$! for -- sends the summaries of its open windows and a "stopped"
$! notice, logs anything it could not send, writes its last line to
$! VMSNOTIFY.LOG and exits.
$!
$! In the kit the agent runs as its own account, so the stop file is
$! made readable and deletable by it, and watching the process exit
$! needs WORLD: run this as SYSTEM.
$!
$! Not STOP/IDENTIFICATION: that deletes the process without running
$! anything, so whatever was queued is lost and the log never says so.
$! If this procedure reports no answer, STOP/ID is the fallback, and the
$! last "waiting" line in VMSNOTIFY.LOG is what it lost.
$!
$ set noon
$ say := write sys$output
$ proc = f$environment("PROCEDURE")
$ root = f$parse(proc,,,"DEVICE") + f$parse(proc,,,"DIRECTORY")
$ pdir = f$parse(proc,,,"DIRECTORY","NO_CONCEAL") - "][" - "><"
$ top = f$parse(proc,,,"DEVICE","NO_CONCEAL") + -
        f$extract(0, f$length(pdir) - 5, pdir)
$ kit = f$extract(f$length(pdir) - 5, 5, pdir) .eqs. ".COM]" .and. -
        f$search(top + ".BIN]VMSNOTIFY_LAUNCH.EXE") .nes. ""
$ logd = root
$ account = ""
$ if kit
$ then
$     logd = top + ".LOG]"
$     account = f$edit(f$trnlnm("VMSNOTIFY$USER", "LNM$SYSTEM_TABLE",, -
                                "EXECUTIVE"), "UPCASE,TRIM")
$     if .not. f$privilege("WORLD") then -
          say "vmsnotify: without WORLD this cannot see the agent's process; run it as SYSTEM"
$ endif
$ stop = logd + "VMSNOTIFY.STOP"
$ log = logd + "VMSNOTIFY.LOG"
$!
$ create 'stop'
$ if kit then set file/protection=(s:rwed,o:rwed,g,w:rd) 'stop'
$ say "vmsnotify: stop requested"
$!
$! The acknowledgement: within a second or two if it is running.
$ count = 0
$ ack_loop:
$   if f$search(stop) .eqs. "" then goto acknowledged
$   wait 00:00:01
$   count = count + 1
$   if count .lt. 10 then goto ack_loop
$ say "vmsnotify: no acknowledgement in 10 s. Is it running?"
$ say "  SHOW SYSTEM/PROCESS=VMSNOTIFY"
$! Left in place, the file would stop the next start at once.
$ delete/nolog 'stop';*
$ say "The stop file has been deleted again, so it will not stop the next"
$ say "start (VMSNOTIFY_START.COM would delete it too)."
$ ! %X10000002: an error in $STATUS, but with the message inhibited,
$ ! since the lines above say what is wrong (a bare 2 prints NOMSG).
$ exit %X10000002
$!
$! Then the exit, after its last attempt to send: up to the configured
$! timeout per queued message when an endpoint is down. In the kit the
$! account must match too, so another user's VMSNOTIFY is not waited for.
$ acknowledged:
$ say "vmsnotify: acknowledged; waiting for it to finish sending"
$ count = 0
$ exit_loop:
$   ctx = ""
$ find_loop:
$     pid = f$pid(ctx)
$     if pid .eqs. "" then goto gone
$     if f$getjpi(pid, "PRCNAM") .nes. "VMSNOTIFY" then goto find_loop
$     if kit .and. f$edit(f$getjpi(pid, "USERNAME"), "TRIM") .nes. account then -
          goto find_loop
$   tmp = f$context("PROCESS", ctx, "CANCEL")
$   wait 00:00:01
$   count = count + 1
$   if count .lt. 60 then goto exit_loop
$ say "vmsnotify: still running after 60 s, process ''pid'. See"
$ say "  TYPE ''log'"
$ exit %X10000002
$ gone:
$ say "vmsnotify: stopped. Its summary is the last line of"
$ say "  ''log'"
$ exit 1
