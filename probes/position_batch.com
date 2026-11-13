$! A second batch job: a fresh process, a fresh image activation.
$ old_default = f$environment("DEFAULT")
$! The work directory is the one above this procedure's (probes/).
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
         f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ set default [-]
$ work = f$environment("DEFAULT")
$ exe = f$extract(0, f$length(work) - 1, work) + ".BUILD]probe_position.exe"
$ show process
$ pp := $'exe'
$ pp "resume" "TEST.STATE" "7"
$ exit 1
