$! vmsnotify_start.com -- start the vmsnotify agent as a detached process
$!
$!     @dev:[dir.VMSNOTIFY]VMSNOTIFY_START     by hand, or from
$!                                             SYS$MANAGER:SYSTARTUP_VMS.COM
$!     @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_START    installed from the kit; at
$!                                             boot, SYS$STARTUP:VMSNOTIFY$STARTUP
$!
$! Everything is found relative to this file's own directory, in one of
$! two layouts (docs/design.md, "The installation kit"; the kit's side
$! is copied from vmsotel_start.com):
$!
$!   the source tree            the kit, VMSNOTIFY$ROOT:
$!   VMSNOTIFY.CONF             [CONF]VMSNOTIFY.CONF    the configuration
$!   VMSNOTIFY.LOG              [LOG]VMSNOTIFY.LOG      the agent's log
$!   VMSNOTIFY_RUN.LOG          [LOG]VMSNOTIFY_RUN.LOG  DCL's, before the agent
$!   VMSNOTIFY.STOP             [LOG]VMSNOTIFY.STOP     VMSNOTIFY_STOP's request
$!   VMSNOTIFY.POS              [DATA]VMSNOTIFY.POS     the read position
$!   [.BUILD]VMSNOTIFY*.EXE     [BIN]                   from build_vms
$!   VMSNOTIFY_RUN, _STOP.COM   [COM]
$!
$! It is the kit's when this file is in a [COM] directory with
$! [BIN]VMSNOTIFY_LAUNCH.EXE beside it.
$!
$! The source tree: RUN/DETACHED of LOGINOUT, so that the process has
$! DCL and can be given arguments, running as the UIC that starts it.
$! The privileges are always NETMBX and TMPMBX (the sockets) and READALL
$! (the operator log and the audit journal, both read by default;
$! findings 12, 33, 36). Never WORLD: the agent does not look at other
$! processes.
$!
$! The kit: never as SYSTEM, whose system-group UIC reaches nearly every
$! file whatever its privileges. The account is the system logical
$! VMSNOTIFY$USER, set by VMSNOTIFY$CONFIGURE.COM; it must exist and have
$! a UIC above MAXSYSGROUP. VMSNOTIFY_LAUNCH.EXE starts the process as
$! that account by persona, since RUN/DETACHED/UIC would keep this
$! process's username and authorized privileges. That needs IMPERSONATE,
$! and WORLD to see whether the account's agent is already running: run
$! it as SYSTEM. The account's authorized privileges are NETMBX, TMPMBX
$! and READALL, as VMSNOTIFY$CONFIGURE sets them.
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
$! The kit's VMSNOTIFY$ROOT is a concealed rooted logical: the physical
$! name of [COM] ends in ".COM]" whichever way this was called.
$ pdir = f$parse(proc,,,"DIRECTORY","NO_CONCEAL") - "][" - "><"
$ top = f$parse(proc,,,"DEVICE","NO_CONCEAL") + -
        f$extract(0, f$length(pdir) - 5, pdir)
$ kit = f$extract(f$length(pdir) - 5, 5, pdir) .eqs. ".COM]" .and. -
        f$search(top + ".BIN]VMSNOTIFY_LAUNCH.EXE") .nes. ""
$ privs = "NETMBX,TMPMBX,READALL"
$ if kit
$ then
$     conf = top + ".CONF]VMSNOTIFY.CONF"
$     logd = top + ".LOG]"
$     bin  = top + ".BIN]"
$     com  = top + ".COM]"
$ else
$     conf = root + "VMSNOTIFY.CONF"
$     logd = root
$     bin  = dev + f$extract(0, f$length(dir) - 1, dir) + ".BUILD]"
$     com  = root
$ endif
$!
$ if f$search(conf) .eqs. ""
$ then
$     say "vmsnotify: no configuration. Create ''conf'"
$     if kit then say "  for example by @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE, then start again."
$     if .not. kit then say "  from ''root'VMSNOTIFY.CONF.EXAMPLE, then start again."
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
$ account = ""
$ if kit
$ then
$     ! From the system table, in executive mode, only: not a job or
$     ! group table another user could write.
$     account = f$edit(f$trnlnm("VMSNOTIFY$USER", "LNM$SYSTEM_TABLE",, -
                                "EXECUTIVE"), "UPCASE,TRIM")
$     if account .eqs. ""
$     then
$         say "vmsnotify: no account. Run @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE"
$         say "  once, as SYSTEM; it creates the account and defines VMSNOTIFY$USER."
$         exit %X10000002
$     endif
$     uicnum = f$identifier(account, "NAME_TO_NUMBER")
$     if uicnum .eq. 0
$     then
$         say "vmsnotify: VMSNOTIFY$USER names ''account', which is not an account."
$         exit %X10000002
$     endif
$     if uicnum / 65536 .le. f$getsyi("MAXSYSGROUP")
$     then
$         say "vmsnotify: refusing to run the agent as ''account', which has a"
$         say "  system UIC, ", f$fao("!%U", uicnum), ". It needs an account of its own"
$         say "  (@VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE)."
$         exit %X10000002
$     endif
$     if .not. f$privilege("IMPERSONATE") .or. .not. f$privilege("WORLD")
$     then
$         say "vmsnotify: starting the agent as ''account' needs IMPERSONATE, and"
$         say "  WORLD to see whether it is already running: run this as SYSTEM."
$         exit %X10000002
$     endif
$ endif
$!
$! One agent per system: process names are unique within a UIC group,
$! so a second start would fail anyway, less clearly. In the kit the
$! name and the account must both match, so that another user's process
$! called VMSNOTIFY is not taken for it. In the source tree only this
$! user's processes are visible without WORLD, which is all that can
$! clash.
$!
$ ctx = ""
$ find_loop:
$   pid = f$pid(ctx)
$   if pid .eqs. "" then goto not_running
$   if f$getjpi(pid, "PRCNAM") .nes. "VMSNOTIFY" then goto find_loop
$   if kit .and. f$edit(f$getjpi(pid, "USERNAME"), "TRIM") .nes. account then -
        goto find_loop
$ tmp = f$context("PROCESS", ctx, "CANCEL")
$ say "vmsnotify: already running, process ''pid'. Stop it first with"
$ if kit then say "  @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP"
$ if .not. kit then say "  @''root'VMSNOTIFY_STOP"
$ exit %X10000002
$ not_running:
$!
$! A stop request left over from last time would stop the new agent at
$! once.
$ if f$search(logd + "VMSNOTIFY.STOP") .nes. "" then -
      delete/nolog 'logd'VMSNOTIFY.STOP;*
$!
$ if kit then goto launch
$!
$! Quotas are stated rather than left to the PQL defaults: TLS wants
$! buffered I/O and buffer space. These are modest (vmsotel's, proven on
$! all four machines), and VMSNOTIFY_LAUNCH.EXE gives the same.
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
$!
$! The kit: as the account, by persona. The process gets the account's
$! authorized privileges, which VMSNOTIFY$CONFIGURE set; VMSNOTIFY_RUN
$! enables the three the agent needs, and says so in VMSNOTIFY_RUN.LOG
$! if one is not authorized.
$ launch:
$ if f$search(logd + "VMSNOTIFY_RUN.LOG") .nes. "" then -
      purge/nolog/keep=5 'logd'VMSNOTIFY_RUN.LOG
$ launch := $'bin'VMSNOTIFY_LAUNCH.EXE
$ launch "''account'" "''com'VMSNOTIFY_RUN.COM" "''logd'VMSNOTIFY_RUN.LOG" "VMSNOTIFY"
$ st = $status
$ if (st .and. 1) .eq. 0
$ then
$     say "vmsnotify: the launcher failed; nothing is running."
$     exit st
$ endif
$! LOGINOUT can still fail as the account (a directory it cannot reach,
$! a disusered account): then the process is gone in a moment.
$ wait 00:00:03
$ ctx = ""
$ check_loop:
$   pid = f$pid(ctx)
$   if pid .eqs. "" then goto not_started
$   if f$getjpi(pid, "PRCNAM") .nes. "VMSNOTIFY" then goto check_loop
$   if f$edit(f$getjpi(pid, "USERNAME"), "TRIM") .nes. account then -
        goto check_loop
$ tmp = f$context("PROCESS", ctx, "CANCEL")
$ say "vmsnotify started as ''account', process ''pid', privileges ''privs'."
$ say "  log   : TYPE VMSNOTIFY$ROOT:[LOG]VMSNOTIFY.LOG"
$ say "  stop  : @VMSNOTIFY$ROOT:[COM]VMSNOTIFY_STOP"
$ exit 1
$ not_started:
$ say "vmsnotify: the process as ''account' did not stay up. See"
$ say "  TYPE ''logd'VMSNOTIFY_RUN.LOG, and ACCOUNTING/SINCE=-0:5 for its status."
$ exit %X10000002
