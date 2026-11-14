$! vmsnotify_run.com -- the detached process's command procedure
$!
$! Not run by hand: VMSNOTIFY_START.COM gives it to LOGINOUT. It runs
$! the agent with its configuration, log, stop file and position file,
$! and exits when the agent does. They are found as VMSNOTIFY_START
$! finds them: beside this file, in the source tree.
$!
$! TODO(kit): the kit's layout ([CONF], [LOG], [DATA], [BIN]) goes where
$! the paths are set below, as in vmsotel_run.com.
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
$ conf = root + "VMSNOTIFY.CONF"
$ logd = root
$ bin  = dev + f$extract(0, f$length(dir) - 1, dir) + ".BUILD]"
$ com  = root
$! Relative names in the configuration (token_file, cafile) are looked
$! for in the default directory.
$ set default 'logd'
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
          "--position" "''logd'VMSNOTIFY.POS"
$ st = $status
$ write sys$output f$time(), " vmsnotify_run: agent exited, status ", st
$ show process/accounting
$ exit st
