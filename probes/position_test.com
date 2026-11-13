$! P1 "A": steps 1-3 only; "B": from step 4 on (a separate batch job runs
$! position_batch.com in between: a queue with one executor cannot be
$! waited on from inside its own job). No P1: everything.
$! position_test.com -- does a saved read position survive a new process?
$ set noon
$ old_default = f$environment("DEFAULT")
$! The work directory is the one above this procedure's (probes/).
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
         f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ set default [-]
$ work = f$environment("DEFAULT")
$ exe = f$extract(0, f$length(work) - 1, work) + ".BUILD]probe_position.exe"
$ if f$search(exe) .eqs. "" then goto noexe
$ pp := $'exe'
$ say := write sys$output
$ say "node ", f$getsyi("NODENAME"), " ", f$getsyi("VERSION"), " ", f$getsyi("ARCH_NAME")
$ say "user ", f$getjpi("","USERNAME")
$ show process/privileges
$ if p1 .eqs. "B" then goto stage_b
$ delete/nolog test.log;*,test.state;*
$ say "=== 1. create TEST.LOG with 10 records"
$ pp "create" "TEST.LOG" "10"
$ say "=== 2. save (record 3 from the end)"
$ pp "save" "TEST.LOG" "TEST.STATE"
$ type test.state
$ say "=== 3. append 5"
$ pp "append" "TEST.LOG" "5"
$ if p1 .eqs. "A" then goto done
$ stage_b:
$ say "=== 4. resume in a spawned subprocess; expect 7 after"
$ spawn/wait/output=resume1.out pp "resume" "TEST.STATE" "7"
$ type resume1.out
$ say "=== 5. new version of TEST.LOG (create 4 records)"
$ pp "create" "TEST.LOG" "4"
$ directory test.log;*
$ say "--- resume by explicit old version"
$ pp "resume" "TEST.STATE" "7"
$ say "--- resume-latest"
$ pp "resume-latest" "TEST.STATE"
$ say "=== 6. delete the old version (;1 of the first create)"
$ delete/nolog test.log;1
$ directory test.log;*
$ pp "resume" "TEST.STATE" "7"
$ say "=== 7. real logs, read-only"
$ pp "save" "SYS$MANAGER:OPERATOR.LOG" "OPER.STATE"
$ pp "resume" "OPER.STATE"
$ pp "resume-latest" "OPER.STATE"
$ pp "save" "SYS$MANAGER:SECURITY.AUDIT$JOURNAL" "AUDIT.STATE"
$ pp "resume" "AUDIT.STATE"
$ pp "resume-latest" "AUDIT.STATE"
$ goto done
$ noexe:
$ write sys$output "probe_position.exe missing"
$ done:
$ set default 'old_default'
$ say "POSITION-TEST-END"
$ exit 1
