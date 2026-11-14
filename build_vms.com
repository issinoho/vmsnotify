$! build_vms.com -- build the vmsnotify agent on OpenVMS (x86, IA64, Alpha)
$!
$! Usage, from any directory:
$!
$!     @[.vmsnotify]build_vms            build VMSNOTIFY.EXE, VMSNOTIFY_TLS.EXE and
$!                                       VMSNOTIFY_LAUNCH.EXE (the kit's launcher)
$!     @[.vmsnotify]build_vms DRYRUN     build, then run the agent with
$!                                       --dry-run --cycles 2 against the
$!                                       real operator log and audit journal
$!                                       (READALL), sending nothing
$!     @[.vmsnotify]build_vms CLEAN      delete [.build]VMSNOTIFY*.EXE and
$!                                       the agent's objects
$!
$! Capture everything for pasting back with /OUTPUT:
$!
$!     @[.vmsnotify]build_vms/OUTPUT=build.log
$!
$! A second parameter forces an OpenSSL family for VMSNOTIFY_TLS.EXE, as
$! build_probes.com allows:  @[.vmsnotify]build_vms "" SSL111
$!
$! What the compiles and links rest on, all proven by vmsotel's
$! build_vms.com on the same machines: /STANDARD=C99,
$! PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES (or every POSIX name fails to
$! link), _SOCKADDR_LEN for the socket code, no /POINTER_SIZE for the
$! system-service code (its item lists are item_list_3 only with 32-bit
$! pointers), and /POINTER_SIZE=32 for the code that calls the OpenSSL
$! ..._SHR32 images. The headers are chosen by the OPENSSL logical,
$! defined /JOB to match the image and deassigned on the way out.
$!
$! Every compile and every LINK is checked. An undefined symbol is only
$! a warning to LINK, and the image it writes runs until it reaches the
$! missing routine, so an image whose link was not clean is deleted.
$!
$! No VAX branch: OpenSSL and /STANDARD=C99 are not there. On Alpha
$! the compiles add /FLOAT=IEEE_FLOAT.
$!
$! Keep this file, descrip.mms and the Makefile in step: a source file
$! added to one must be added to all three (tools/check_build_files.py).
$!
$ set noon
$ say := write sys$output
$ old_default = f$environment("DEFAULT")
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
         f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$!
$ say "vmsnotify build, ", f$getsyi("NODENAME"), ", OpenVMS ", -
      f$getsyi("VERSION"), " ", f$getsyi("ARCH_NAME")
$!
$ arch = f$getsyi("ARCH_NAME")
$ if arch .eqs. "VAX"
$ then
$     say "VAX is not supported: no OpenSSL and no /STANDARD=C99"
$     goto finish
$ endif
$ if p1 .eqs. "CLEAN" then goto clean
$!
$ if f$search("build.dir") .eqs. "" then create/directory [.build]
$!
$!---------------------------------------------------------------------
$! Compile
$!---------------------------------------------------------------------
$!
$! Built by concatenation, not one continued string: a "-" inside quotes
$! would fold the next line's spaces into the list.
$ cc_base = "/STANDARD=C99/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES" + -
            "/INCLUDE_DIRECTORY=([.src.model],[.src.notify],[.src.platform]," + -
            "[.src.transport],[.src.sources],[.src.agent])"
$ if arch .eqs. "Alpha" then cc_base = cc_base + "/FLOAT=IEEE_FLOAT"
$ failed = ""
$ warned = ""
$ built = ""
$ cflags = ""
$!
$ say ""
$ say "compiling"
$ cobj = "vn_types"
$ csrc = "[.src.model]vn_types.c"
$ gosub compile
$ cobj = "logparse"
$ csrc = "[.src.model]logparse.c"
$ gosub compile
$ cobj = "rules"
$ csrc = "[.src.model]rules.c"
$ gosub compile
$ cobj = "throttle"
$ csrc = "[.src.model]throttle.c"
$ gosub compile
$ cobj = "json"
$ csrc = "[.src.notify]json.c"
$ gosub compile
$ cobj = "format"
$ csrc = "[.src.notify]format.c"
$ gosub compile
$ cobj = "endpoint"
$ csrc = "[.src.notify]endpoint.c"
$ gosub compile
$ cobj = "config"
$ csrc = "[.src.agent]config.c"
$ gosub compile
$ cobj = "queue"
$ csrc = "[.src.transport]queue.c"
$ gosub compile
$ cobj = "vms_logs"
$ csrc = "[.src.sources.vms]vms_logs.c"
$ gosub compile
$ cobj = "vms_sys"
$ csrc = "[.src.sources.vms]vms_sys.c"
$ gosub compile
$! _SOCKADDR_LEN selects the BSD 4.4 socket structures getaddrinfo needs.
$ cobj = "platform_posix"
$ csrc = "[.src.platform]platform_posix.c"
$ cflags = "/DEFINE=(_SOCKADDR_LEN)"
$ gosub compile
$ cflags = ""
$ cobj = "http"
$ csrc = "[.src.transport]http.c"
$ gosub compile
$ cobj = "agent"
$ csrc = "[.src.agent]agent.c"
$ gosub compile
$!
$ core = "[.build]vn_types.obj,[.build]logparse.obj,[.build]rules.obj," + -
         "[.build]throttle.obj,[.build]json.obj,[.build]format.obj," + -
         "[.build]endpoint.obj,[.build]config.obj,[.build]queue.obj," + -
         "[.build]vms_logs.obj,[.build]vms_sys.obj,[.build]platform_posix.obj"
$ if failed .nes. "" then goto summary
$!
$!---------------------------------------------------------------------
$! Link VMSNOTIFY.EXE: plain HTTP
$!---------------------------------------------------------------------
$!
$ say "linking vmsnotify.exe"
$ link /EXECUTABLE=[.build]vmsnotify.exe [.build]agent.obj,[.build]http.obj,'core'
$ if $severity .ne. 1
$ then
$     failed = failed + " vmsnotify.exe"
$     if f$search("[.build]vmsnotify.exe") .nes. "" then -
          delete/nolog [.build]vmsnotify.exe;*
$ else
$     built = built + " vmsnotify.exe"
$ endif
$!
$!---------------------------------------------------------------------
$! OpenSSL for VMSNOTIFY_TLS.EXE
$!---------------------------------------------------------------------
$!
$! The ssl image, the crypto image beside it and the headers must all
$! come from one family; this is build_probes.com's search.
$!
$ ssl_candidates = "SYS$LIBRARY:SSL3$LIBSSL_SHR32,SYS$SHARE:SSL3$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL31$LIBSSL_SHR32,SYS$SHARE:SSL31$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL111$LIBSSL_SHR32,SYS$SHARE:SSL111$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL1$LIBSSL_SHR32,SYS$SHARE:SSL1$LIBSSL_SHR32"
$ if p2 .nes. "" then ssl_candidates = "SYS$LIBRARY:" + p2 + "$LIBSSL_SHR32," + -
                                       "SYS$SHARE:" + p2 + "$LIBSSL_SHR32"
$ ssl_lib = ""
$ i = 0
$ ssl_loop:
$   name = f$element(i, ",", ssl_candidates)
$   if name .eqs. "," then goto ssl_done
$   if f$search(name + ".EXE") .nes. ""
$   then
$       ssl_lib = name
$       goto ssl_done
$   endif
$   i = i + 1
$   goto ssl_loop
$ ssl_done:
$ if ssl_lib .eqs. ""
$ then
$     say "no 32-bit libssl image found; vmsnotify_tls.exe not built. Installed:"
$     directory/size/date sys$library:*libssl*.exe,sys$share:*libssl*.exe
$     failed = failed + " vmsnotify_tls.exe"
$     goto summary
$ endif
$ colon = f$locate(":", ssl_lib)
$ at_lib = f$locate("$LIBSSL", ssl_lib)
$ ssl_family = f$extract(colon + 1, at_lib - colon - 1, ssl_lib)
$ crypto_lib = f$extract(0, at_lib, ssl_lib) + "$LIBCRYPTO_SHR32"
$ ssl_include = ssl_family + "$INCLUDE"
$ if f$search(crypto_lib + ".EXE") .eqs. "" .or. f$trnlnm(ssl_include) .eqs. ""
$ then
$     say "found ''ssl_lib' but not ''crypto_lib' or ''ssl_include';"
$     say "not building vmsnotify_tls.exe rather than mixing OpenSSL versions"
$     show logical SSL*$INCLUDE
$     failed = failed + " vmsnotify_tls.exe"
$     goto summary
$ endif
$! tls.c refuses to compile if the headers OPENSSL selects are not the
$! family this link names.
$ ssl_expect = "VN_EXPECT_OPENSSL_3"
$ if ssl_family .eqs. "SSL111" .or. ssl_family .eqs. "SSL1" then -
      ssl_expect = "VN_EXPECT_OPENSSL_1"
$ say "OpenSSL: ''ssl_lib', ''crypto_lib', headers ''ssl_include'"
$ define/job/nolog OPENSSL 'ssl_include':
$ open/write opt [.build]vmsnotify_ssl.opt
$ write opt ssl_lib + "/SHAREABLE"
$ write opt crypto_lib + "/SHAREABLE"
$ close opt
$!
$ say "compiling with TLS"
$ failed_before = failed
$ cobj = "http_tls"
$ csrc = "[.src.transport]http.c"
$ cflags = "/DEFINE=(VN_WITH_TLS)"
$ gosub compile
$ cobj = "agent_tls"
$ csrc = "[.src.agent]agent.c"
$ gosub compile
$! The one file that calls OpenSSL, so the one that states the pointer
$! size of the ..._SHR32 images it links against.
$ cobj = "tls"
$ csrc = "[.src.transport]tls.c"
$ cflags = "/POINTER_SIZE=32/DEFINE=(VN_WITH_TLS," + ssl_expect + ")"
$ gosub compile
$ cflags = ""
$ if failed .nes. failed_before then goto summary
$!
$ say "linking vmsnotify_tls.exe"
$ link /EXECUTABLE=[.build]vmsnotify_tls.exe -
      [.build]agent_tls.obj,[.build]http_tls.obj,[.build]tls.obj,'core', -
      [.build]vmsnotify_ssl.opt/OPTIONS
$ if $severity .ne. 1
$ then
$     failed = failed + " vmsnotify_tls.exe"
$     if f$search("[.build]vmsnotify_tls.exe") .nes. "" then -
          delete/nolog [.build]vmsnotify_tls.exe;*
$ else
$     built = built + " vmsnotify_tls.exe"
$ endif
$!
$!---------------------------------------------------------------------
$! VMSNOTIFY_LAUNCH.EXE: the kit starts the agent as its account with it
$!---------------------------------------------------------------------
$!
$! Persona services and $CREPRC, and OpenSSL's generator for the
$! account's password: so the pointer size of the ..._SHR32 images,
$! like tls.c, and the same options file (copied from vmsotel's).
$ say "compiling and linking vmsnotify_launch.exe"
$ failed_before = failed
$ cobj = "launch"
$ csrc = "[.src.launch]launch.c"
$ cflags = "/POINTER_SIZE=32"
$ gosub compile
$ cflags = ""
$ if failed .nes. failed_before then goto summary
$ link /EXECUTABLE=[.build]vmsnotify_launch.exe [.build]launch.obj, -
      [.build]vmsnotify_ssl.opt/OPTIONS
$ if $severity .ne. 1
$ then
$     failed = failed + " vmsnotify_launch.exe"
$     if f$search("[.build]vmsnotify_launch.exe") .nes. "" then -
          delete/nolog [.build]vmsnotify_launch.exe;*
$ else
$     built = built + " vmsnotify_launch.exe"
$ endif
$!
$ summary:
$ say ""
$ say "built:''built'"
$ if warned .nes. "" then say "compiled with warnings:''warned'  -- paste them"
$ if failed .nes. "" then say "FAILED:''failed'  -- paste the messages above"
$ if p1 .eqs. "DRYRUN" then goto dryrun
$ goto finish
$!
$!---------------------------------------------------------------------
$! DRYRUN: the agent against the real logs, sending nothing. One fake
$! Gotify endpoint (never contacted: --dry-run) and a rule that matches
$! every record, so there is something to see. Needs READALL.
$!---------------------------------------------------------------------
$!
$ dryrun:
$ if f$search("[.build]vmsnotify.exe") .eqs. "" then goto finish
$ say ""
$ say "=== privileges: READALL is needed"
$ show process/privileges
$ open/write cf [.build]dryrun.conf
$ write cf "! written by build_vms.com DRYRUN"
$ write cf "logs.opcom = yes"
$ write cf "logs.audit = yes"
$ write cf "interval = 5"
$ write cf "[endpoint fake]"
$ write cf "type = gotify"
$ write cf "url = http://192.168.0.218:18080"
$ write cf "token = test"
$ write cf "[rule all]"
$ close cf
$ say ""
$ say "=== the two files"
$ directory/size/date sys$manager:operator.log,security.audit$journal
$ vmsnotify := $sys$disk:[.build]vmsnotify.exe
$ say ""
$ say "=== vmsnotify --dry-run --cycles 2"
$ vmsnotify [.build]dryrun.conf --dry-run --cycles 2 --position [.build]dryrun.pos
$ say "=== exit status ", $status
$ goto finish
$!
$!---------------------------------------------------------------------
$! One compile. A warning is reported and the build goes on, as in
$! build_probes.com; an error or worse stops anything linking it.
$!---------------------------------------------------------------------
$!
$ compile:
$   cc 'cc_base' 'cflags' /OBJECT=[.build]'cobj'.obj 'csrc'
$   sev = $severity
$   if sev .eq. 2 .or. sev .eq. 4
$   then
$       failed = failed + " " + cobj
$   else
$       if sev .eq. 0 then warned = warned + " " + cobj
$   endif
$   return
$!
$! CLEAN: the agent's images and objects only; the probes' stay.
$ clean:
$ if f$search("[.build]vmsnotify*.exe") .nes. "" then -
      delete/nolog [.build]vmsnotify*.exe;*
$ if f$search("[.build]vmsnotify_ssl.opt") .nes. "" then -
      delete/nolog [.build]vmsnotify_ssl.opt;*
$ agent_objs = "launch,vn_types,logparse,rules,throttle,json,format,endpoint,config,queue,vms_logs,vms_sys,platform_posix,http,agent,http_tls,agent_tls,tls"
$ i = 0
$ clean_loop:
$   o = f$element(i, ",", agent_objs)
$   if o .eqs. "," then goto clean_done
$   if f$search("[.build]''o'.obj") .nes. "" then -
        delete/nolog [.build]'o'.obj;*
$   i = i + 1
$   goto clean_loop
$ clean_done:
$ say "cleaned"
$!
$ finish:
$ if f$trnlnm("OPENSSL", "LNM$JOB") .nes. "" then deassign/job OPENSSL
$ set default 'old_default'
$ exit 1
