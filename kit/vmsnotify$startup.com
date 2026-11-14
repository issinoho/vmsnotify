$! VMSNOTIFY$STARTUP.COM -- the vmsnotify agent at system startup
$! (Copied from vmsotel's kit, issinoho/vmsotel, MIT, same author; renamed.)
$!
$!   @SYS$STARTUP:VMSNOTIFY$STARTUP          from SYSTARTUP_VMS.COM, after
$!                                         TCP/IP: define VMSNOTIFY$ROOT and
$!                                         VMSNOTIFY$USER, and start the agent
$!                                         if SYS$MANAGER:VMSNOTIFY$CONFIG.COM
$!                                         says AUTOSTART
$!   @SYS$STARTUP:VMSNOTIFY$STARTUP INSTALL  define VMSNOTIFY$ROOT only (PCSI,
$!                                         after installing)
$!   @SYS$STARTUP:VMSNOTIFY$STARTUP REMOVE   stop the agent and deassign both
$!                                         (PCSI, before removing)
$!
$! As SYSTEM. The agent itself runs as its own account (VMSNOTIFY_START).
$!
$ set noon
$ op = f$edit(p1, "UPCASE,TRIM")
$ if op .eqs. "REMOVE" then goto remove
$!
$! This file is in <destination>[SYS$STARTUP]; the product is in
$! <destination>[VMSNOTIFY]. Physical names: the destination may itself
$! be a concealed logical (SYS$COMMON).
$ proc = f$environment("PROCEDURE")
$ dev = f$parse(proc,,,"DEVICE","NO_CONCEAL")
$ dir = f$edit(f$parse(proc,,,"DIRECTORY","NO_CONCEAL"), "UPCASE") - "][" - "><"
$ if f$locate("SYS$STARTUP]", dir) .eq. f$length(dir)
$ then
$     write sys$error "VMSNOTIFY$STARTUP: expected to be in a [SYS$STARTUP] directory, not ''dir'"
$     exit 44
$ endif
$ root = dev + (dir - "SYS$STARTUP]" + "VMSNOTIFY.]" - ".000000")
$ define/system/executive_mode/translation_attributes=concealed/nolog -
      VMSNOTIFY$ROOT 'root'
$ if f$search("VMSNOTIFY$ROOT:[BIN]VMSNOTIFY_LAUNCH.EXE") .eqs. ""
$ then
$     write sys$error "VMSNOTIFY$STARTUP: no VMSNOTIFY$ROOT:[BIN]VMSNOTIFY_LAUNCH.EXE (root ''root')"
$     exit 44
$ endif
$ if op .eqs. "INSTALL" then exit 1
$!
$! At boot: the site settings, written by VMSNOTIFY$CONFIGURE, name the
$! account and say whether to start. Global symbols, as that file
$! assigns them: a local one of the same name would hide them.
$ if f$search("SYS$MANAGER:VMSNOTIFY$CONFIG.COM") .eqs. ""
$ then
$     write sys$output "VMSNOTIFY$STARTUP: not configured; run @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE"
$     exit 1
$ endif
$ vmsnotify_account == ""
$ vmsnotify_autostart == "NO"
$ @SYS$MANAGER:VMSNOTIFY$CONFIG.COM
$ if vmsnotify_account .nes. "" then define/system/executive_mode/nolog -
      VMSNOTIFY$USER 'f$edit(vmsnotify_account, "UPCASE,TRIM")'
$ if f$edit(vmsnotify_autostart, "UPCASE,TRIM") .nes. "YES"
$ then
$     write sys$output "VMSNOTIFY$STARTUP: start at boot is off (SYS$MANAGER:VMSNOTIFY$CONFIG.COM)"
$     exit 1
$ endif
$ @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_START
$ exit 1
$!
$ remove:
$! Stop the agent if the account's VMSNOTIFY process is running; asking
$! one that is not would wait 10 s for an answer.
$ account = f$edit(f$trnlnm("VMSNOTIFY$USER", "LNM$SYSTEM_TABLE"), "UPCASE,TRIM")
$ running = 0
$ ctx = ""
$ rm_loop:
$   pid = f$pid(ctx)
$   if pid .eqs. "" then goto rm_looked
$   if f$getjpi(pid, "PRCNAM") .nes. "VMSNOTIFY" then goto rm_loop
$   if f$edit(f$getjpi(pid, "USERNAME"), "TRIM") .nes. account then goto rm_loop
$ running = 1
$ tmp = f$context("PROCESS", ctx, "CANCEL")
$ rm_looked:
$ if f$trnlnm("VMSNOTIFY$ROOT", "LNM$SYSTEM_TABLE") .nes. ""
$ then
$     if running .and. f$search("VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP.COM") .nes. "" then -
          @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP
$     deassign/system/executive_mode VMSNOTIFY$ROOT
$ endif
$ if f$trnlnm("VMSNOTIFY$USER", "LNM$SYSTEM_TABLE") .nes. "" then -
      deassign/system/executive_mode VMSNOTIFY$USER
$ exit 1
