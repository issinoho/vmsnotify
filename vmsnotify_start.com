$! vmsnotify_start.com -- start the vmsnotify agent as a detached process
$!
$!     @dev:[dir.VMSNOTIFY]VMSNOTIFY_START     by hand, or from
$!                                             SYS$MANAGER:SYSTARTUP_VMS.COM
$!
$! Everything is found relative to this file's own directory (the source
$! tree):
$!
$!   VMSNOTIFY.CONF         the configuration (from VMSNOTIFY.CONF.EXAMPLE)
$!   VMSNOTIFY.LOG          the agent's log
$!   VMSNOTIFY_RUN.LOG      DCL's, before the agent
$!   VMSNOTIFY.STOP         VMSNOTIFY_STOP's request
$!   VMSNOTIFY.POS          the read position, kept across restarts
$!   [.BUILD]VMSNOTIFY*.EXE from build_vms
$!   VMSNOTIFY_RUN, _STOP.COM
$!
$! TODO(kit): when the PCSI kit exists, this is where its layout is
$! chosen, as vmsotel_start.com does: the kit's [COM] directory with
$! [BIN]VMSNOTIFY_LAUNCH.EXE beside it, the configuration in [CONF], the
$! logs in [LOG], the position in [DATA], and the process started as the
$! account VMSNOTIFY$USER by persona rather than by RUN/DETACHED below.
$! Not written yet; only the source tree works.
$!
$! RUN/DETACHED of LOGINOUT, so that the process has DCL and can be
$! given arguments, running as the UIC that starts it. The privileges
$! are always NETMBX and TMPMBX (the sockets) and READALL (the operator
$! log and the audit journal, both read by default; findings 12, 33,
$! 36). Never WORLD: the agent does not look at other processes.
$!
$! It does not restart itself. An agent that came back silently after
$! failing would hide the failure; VMSNOTIFY.LOG says why it stopped.
$!
$ set noon
$ say := write sys$output
$ proc = f$environment("PROCEDURE")
$ dev = f$parse(proc,,,"DEVICE")
$ dir = f$parse(proc,,,"DIRECTORY")
$ root = dev + dir
$ conf = root + "VMSNOTIFY.CONF"
$ logd = root
$ bin  = dev + f$extract(0, f$length(dir) - 1, dir) + ".BUILD]"
$ com  = root
$ privs = "NETMBX,TMPMBX,READALL"
$!
$ if f$search(conf) .eqs. ""
$ then
$     say "vmsnotify: no configuration. Create ''conf'"
$     say "  from ''root'VMSNOTIFY.CONF.EXAMPLE, then start again."
$     ! %X10000002: an error in $STATUS, but with the message inhibited,
$     ! since the lines above say what is wrong (a bare 2 prints NOMSG).
$     exit %X10000002
$ endif
$ if f$search(bin + "VMSNOTIFY_TLS.EXE") .eqs. "" .and. -
     f$search(bin + "VMSNOTIFY.EXE") .eqs. ""
$ then
$     say "vmsnotify: not built. Run @''root'BUILD_VMS first."
$     exit %X10000002
$ endif
$ if f$search(com + "VMSNOTIFY_RUN.COM") .eqs. ""
$ then
$     say "vmsnotify: cannot find ''com'VMSNOTIFY_RUN.COM"
$     exit %X10000002
$ endif
$!
$! One agent per user: process names are unique within a UIC group, so
$! a second start would fail anyway, less clearly. Only this user's
$! processes are visible without WORLD, which is all that can clash.
$!
$ ctx = ""
$ find_loop:
$   pid = f$pid(ctx)
$   if pid .eqs. "" then goto not_running
$   if f$getjpi(pid, "PRCNAM") .nes. "VMSNOTIFY" then goto find_loop
$ tmp = f$context("PROCESS", ctx, "CANCEL")
$ say "vmsnotify: already running, process ''pid'. Stop it first with"
$ say "  @''root'VMSNOTIFY_STOP"
$ exit %X10000002
$ not_running:
$!
$! A stop request left over from last time would stop the new agent at
$! once.
$ if f$search(logd + "VMSNOTIFY.STOP") .nes. "" then -
      delete/nolog 'logd'VMSNOTIFY.STOP;*
$!
$! Quotas are stated rather than left to the PQL defaults: TLS wants
$! buffered I/O and buffer space. These are modest (vmsotel's, proven on
$! all four machines).
$!
$ run/detached sys$system:loginout.exe -
      /input='com'VMSNOTIFY_RUN.COM -
      /output='logd'VMSNOTIFY_RUN.LOG -
      /process_name=VMSNOTIFY -
      /privileges=(NOSAME,'privs') -
      /ast_limit=100 /buffer_limit=200000 /enqueue_limit=500 -
      /file_limit=100 /io_buffered=100 /io_direct=100 -
      /page_file=300000 /queue_limit=20 -
      /working_set=4096 /maximum_working_set=16384 /extent=32768
$ st = $status
$!
$! SET NOON is on, so the status has to be looked at, or a failed RUN
$! would be followed by a message saying all is well.
$ if (st .and. 1) .eq. 0
$ then
$     say "vmsnotify: RUN/DETACHED failed; nothing is running."
$     exit st
$ endif
$ say "vmsnotify started, privileges NOSAME,''privs'."
$ say "  log   : TYPE ''root'VMSNOTIFY.LOG"
$ say "  stop  : @''root'VMSNOTIFY_STOP"
$ exit 1
