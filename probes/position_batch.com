$! A second batch job: a fresh process, a fresh image activation.
$ set default USER$ROOT:[IAIN.VMSNOTIFY]
$ show process
$ pp := $USER$ROOT:[IAIN.VMSNOTIFY.BUILD]probe_position.exe
$ pp "resume" "TEST.STATE" "7"
$ exit 1
