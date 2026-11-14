$! MAKE_KIT.COM -- build vmsnotify's PCSI kit for this node's architecture
$! (copied from vmsotel's kit/make_kit.com, issinoho/vmsotel, MIT, same
$! author; VAX and @NOTVAX@ left out, as this kit has no VAX)
$!
$!   @dev:[dir.VMSNOTIFY.KIT]MAKE_KIT          after @[.VMSNOTIFY]BUILD_VMS
$!
$! Writes ISSINOHO-<base>-VMSNOTIFY-<version>-1.PCSI to [.KIT_<arch>] in
$! the vmsnotify tree. Needs [.BUILD]VMSNOTIFY.EXE, VMSNOTIFY_TLS.EXE and
$! VMSNOTIFY_LAUNCH.EXE, and refuses agent images whose --version is not
$! VN_VERSION in src/model/version.h. PRODUCT PACKAGE needs no privilege.
$!
$! The product description and text module are the templates in
$! [.KIT] with @PRODUCER@, @BASE@, @PCSIVERSION@, @VERSION@ and @ARCH@
$! filled in; README.VMS too. tools/check_kit.py, in make check, checks
$! that every file the description names is gathered here.
$!
$ set noon
$ set process/parse_style=extended
$ say := write sys$output
$ status = 44
$ saved_default = f$environment("DEFAULT")
$ proc = f$environment("PROCEDURE")
$ set default 'f$parse(proc,,,"DEVICE")''f$parse(proc,,,"DIRECTORY")'
$ set default [-]
$ arch = f$edit(f$getsyi("ARCH_NAME"), "UPCASE")
$ base = "I64VMS"
$ archname = "Integrity"
$ if arch .eqs. "X86_64" then base = "X86VMS"
$ if arch .eqs. "ALPHA" then base = "AXPVMS"
$ if arch .eqs. "X86_64" then archname = "x86-64"
$ if arch .eqs. "ALPHA" then archname = "Alpha"
$ producer = "ISSINOHO"
$!
$! ---- the version, from src/model/version.h alone ----
$! The value between the quotes on the line that starts with the
$! #define. Compared with f$extract, not f$locate(...) .eq. 0: f$locate
$! returns the length when it finds nothing, which for an empty line is
$! 0, so every blank line matched and the last set the version to
$! f$element's "not there", the delimiter itself -- a lone quote (x86,
$! the first two MAKE_KITs).
$ q = " "
$ q[0,8] = 34
$ version = ""
$ pcsiversion = ""
$ open/read/error=no_version vh [.src.model]version.h
$ vh_loop:
$   read/end_of_file=vh_done vh line
$   if f$extract(0, 19, line) .eqs. "#define VN_VERSION "
$   then
$       version = f$element(1, q, line)
$   endif
$   if f$extract(0, 24, line) .eqs. "#define VN_PCSI_VERSION "
$   then
$       pcsiversion = f$element(1, q, line)
$   endif
$   goto vh_loop
$ vh_done:
$ close vh
$ no_version:
$ if version .eqs. "" .or. pcsiversion .eqs. "" .or. -
     version .eqs. q .or. pcsiversion .eqs. q
$ then
$     say "MAKE_KIT: no VN_VERSION or VN_PCSI_VERSION in [.src.model]version.h"
$     goto done
$ endif
$!
$! ---- the images, and the version they report ----
$ images = "VMSNOTIFY,VMSNOTIFY_TLS,VMSNOTIFY_LAUNCH"
$ i = 0
$ img_loop:
$   img = f$element(i, ",", images)
$   if img .eqs. "," then goto img_done
$   if f$search("[.BUILD]''img'.EXE") .eqs. ""
$   then
$       say "MAKE_KIT: no [.BUILD]''img'.EXE; @BUILD_VMS first"
$       goto done
$   endif
$   i = i + 1
$   goto img_loop
$ img_done:
$ say "MAKE_KIT: version.h says ''version', PCSI ''pcsiversion'"
$ agents = "VMSNOTIFY,VMSNOTIFY_TLS"
$ i = 0
$ ver_loop:
$   img = f$element(i, ",", agents)
$   if img .eqs. "," then goto ver_done
$   agent = "$" + f$search("[.BUILD]''img'.EXE")
$   define/user sys$output [.BUILD]MAKE_KIT_VERSION.TMP
$   agent "--version"
$   got = ""
$   open/read v [.BUILD]MAKE_KIT_VERSION.TMP
$   read/end_of_file=ver_read v got
$   ver_read:
$   close v
$   delete/nolog [.BUILD]MAKE_KIT_VERSION.TMP;*
$   if got .nes. "vmsnotify " + version
$   then
$       say "MAKE_KIT: ''img'.EXE says """, got, """; the kit is ", version, ". Rebuild."
$       goto done
$   endif
$   i = i + 1
$   goto ver_loop
$ ver_done:
$!
$! ---- gather the files, flat: PRODUCT PACKAGE finds each by name ----
$ out = "[.KIT_''arch']"
$ mat = "[.KIT_''arch'.MAT]"
$ if f$search("KIT_''arch'.DIR") .eqs. "" then create/directory 'out'
$ if f$search("[.KIT_''arch']MAT.DIR") .eqs. "" then create/directory 'mat'
$ if f$search("''out'*.PCSI;*") .nes. "" then delete/nolog 'out'*.PCSI;*
$ if f$search("''out'*.PCSI$*;*") .nes. "" then delete/nolog 'out'*.PCSI$*;*
$ if f$search("''mat'*.*;*") .nes. "" then delete/nolog 'mat'*.*;*
$ copy/nolog [.BUILD]VMSNOTIFY.EXE,VMSNOTIFY_TLS.EXE,VMSNOTIFY_LAUNCH.EXE 'mat'
$ copy/nolog []VMSNOTIFY_START.COM,VMSNOTIFY_RUN.COM,VMSNOTIFY_STOP.COM 'mat'
$ copy/nolog [.KIT]VMSNOTIFY$CONFIGURE.COM,VMSNOTIFY$STARTUP.COM,VMSNOTIFY$SHUTDOWN.COM 'mat'
$ copy/nolog []VMSNOTIFY.CONF.EXAMPLE 'mat'VMSNOTIFY.CONF_EXAMPLE
$ copy/nolog [.DOCS]OPERATIONS.MD 'mat'OPERATIONS.MD
$ copy/nolog []LICENSE. 'mat'LICENSE.
$ in = "[.KIT]README.VMS"
$ to = mat + "README.VMS"
$ gosub fill
$ in = "[.KIT]VMSNOTIFY.PCSI$DESC"
$ to = out + "PRODUCT-''base'.PCSI$DESC"
$ gosub fill
$ in = "[.KIT]VMSNOTIFY.PCSI$TEXT"
$ to = out + "PRODUCT-''base'.PCSI$TEXT"
$ gosub fill
$ matspec = f$parse(mat,,,"DEVICE","NO_CONCEAL") + -
            f$parse(mat,,,"DIRECTORY","NO_CONCEAL")
$!
$ pkgopt = "/options=noconfirm"
$ say "MAKE_KIT: ''producer' ''base' VMSNOTIFY ''pcsiversion' (vmsnotify ''version')"
$ product package VMSNOTIFY -
      /producer='producer' /base_system='base' /version='pcsiversion' -
      /source='out'PRODUCT-'base'.PCSI$DESC -
      /material='matspec' -
      /destination='out' -
      /format=sequential -
      'pkgopt' /log
$ status = $status
$ kit = f$search("''out'*.PCSI")
$ if kit .nes. "" then say "MAKE_KIT: kit ", kit
$ if kit .eqs. "" then status = 44
$ done:
$ set default 'saved_default'
$ exit status
$!
$! Copies file "in" to "to", replacing each @NAME@ by its value.
$ fill:
$ open/read fin 'in'
$ open/write fout 'to'
$ fill_line:
$   read/end_of_file=fill_end fin line
$   t = 0
$ fill_token:
$   name = f$element(t, ",", "PRODUCER,BASE,PCSIVERSION,VERSION,ARCH")
$   if name .eqs. "," then goto fill_write
$   tok = "@" + name + "@"
$   if name .eqs. "PRODUCER" then val = producer
$   if name .eqs. "BASE" then val = base
$   if name .eqs. "PCSIVERSION" then val = pcsiversion
$   if name .eqs. "VERSION" then val = version
$   if name .eqs. "ARCH" then val = archname
$ fill_again:
$   at = f$locate(tok, line)
$   if at .eq. f$length(line) then goto fill_next
$   line = f$extract(0, at, line) + val + f$extract(at + f$length(tok), 9999, line)
$   goto fill_again
$ fill_next:
$   t = t + 1
$   goto fill_token
$ fill_write:
$   write fout line
$   goto fill_line
$ fill_end:
$ close fin
$ close fout
$ return
