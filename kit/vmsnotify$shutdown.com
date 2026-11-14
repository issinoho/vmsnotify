$! VMSNOTIFY$SHUTDOWN.COM -- stop the vmsnotify agent at system shutdown
$! (Copied from vmsotel's kit, issinoho/vmsotel, MIT, same author; renamed.)
$!
$!   @SYS$STARTUP:VMSNOTIFY$SHUTDOWN         from SYS$MANAGER:SYSHUTDWN.COM
$!
$! As SYSTEM. VMSNOTIFY_STOP asks the agent to stop, so that it makes one
$! more attempt to send what it has queued and logs what it could not;
$! the process deletion at shutdown would lose it silently.
$!
$ set noon
$ if f$trnlnm("VMSNOTIFY$ROOT", "LNM$SYSTEM_TABLE") .eqs. "" then exit 1
$ if f$search("VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP.COM") .eqs. "" then exit 1
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP
$ exit 1
