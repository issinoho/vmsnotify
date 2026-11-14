$! vmsnotify_run.com -- the detached process's command procedure
$!
$! Not run by hand: VMSNOTIFY_START.COM gives it to LOGINOUT. It runs
$! the agent with its configuration, log, stop file and position file,
$! and exits when the agent does. They are found as VMSNOTIFY_START
$! finds them: beside this file in the source tree, or in the kit's [CONF],
$! [LOG] and [DATA] (the layout is copied from vmsotel_run.com).
$!
$! The privileges are NETMBX, TMPMBX and READALL, given by
$! VMSNOTIFY_START; this shows them first, so that VMSNOTIFY_RUN.LOG
$! records what the agent really ran with.
$!
$! The TLS image is preferred: it also speaks plain HTTP for an endpoint
$! whose url is http://.
$!
$ set noon
$ proc = f$environment("PROCEDURE")
$ dev = f$parse(proc,,,"DEVICE")
$ dir = f$parse(proc,,,"DIRECTORY")
$ root = dev + dir
$ pdir = f$parse(proc,,,"DIRECTORY","NO_CONCEAL") - "][" - "><"
$ top = f$parse(proc,,,"DEVICE","NO_CONCEAL") + -
        f$extract(0, f$length(pdir) - 5, pdir)
$ kit = f$extract(f$length(pdir) - 5, 5, pdir) .eqs. ".COM]" .and. -
        f$search(top + ".BIN]VMSNOTIFY_LAUNCH.EXE") .nes. ""
$ if kit
$ then
$     conf = top + ".CONF]VMSNOTIFY.CONF"
$     logd = top + ".LOG]"
$     datad = top + ".DATA]"
$     bin  = top + ".BIN]"
$ else
$     conf = root + "VMSNOTIFY.CONF"
$     logd = root
$     datad = root
$     bin  = dev + f$extract(0, f$length(dir) - 1, dir) + ".BUILD]"
$ endif
$! Relative names in the configuration (token_file, cafile) are looked
$! for in the default directory: the source tree's, and in the kit [CONF],
$! where the tokens and certificates are kept.
$ if kit then set default 'top'.CONF]
$ if .not. kit then set default 'logd'
$!
$ set process/privileges=(noall,netmbx,tmpmbx,readall)
$ missing = ""
$ if .not. f$privilege("NETMBX") then missing = missing + " NETMBX"
$ if .not. f$privilege("TMPMBX") then missing = missing + " TMPMBX"
$ if .not. f$privilege("READALL") then missing = missing + " READALL"
$ if missing .nes. ""
$ then
$     write sys$output f$time(), " vmsnotify_run: needs", missing, -
          ", which ", f$edit(f$getjpi("", "USERNAME"), "TRIM"), -
          " is not authorized; what needs it will not work."
$     if kit then write sys$output "  Run @VMSNOTIFY$ROOT:[COM]VMSNOTIFY$CONFIGURE again, as SYSTEM."
$ endif
$!
$ exe = bin + "VMSNOTIFY_TLS.EXE"
$ if f$search(exe) .eqs. "" then exe = bin + "VMSNOTIFY.EXE"
$ write sys$output f$time(), " vmsnotify_run: ", exe, " as ", -
      f$edit(f$getjpi("", "USERNAME"), "TRIM")
$ show process/privileges
$!
$! Quoted, so that DCL passes them as written.
$ vmsnotify := $'exe'
$ vmsnotify "''conf'" -
          "--log" "''logd'VMSNOTIFY.LOG" -
          "--stop-file" "''logd'VMSNOTIFY.STOP" -
          "--position" "''datad'VMSNOTIFY.POS"
$ st = $status
$ write sys$output f$time(), " vmsnotify_run: agent exited, status ", st
$ show process/accounting
$ exit st
