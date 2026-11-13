$! build_probes.com -- build the vmsnotify probes on OpenVMS
$!
$!     @build_probes            build probe_position
$!
$! Every LINK is checked for warnings: an undefined symbol is only a
$! warning on VMS, and the image then crashes when it reaches the
$! missing routine, so such an image is deleted here.
$!
$ set noon
$ say := write sys$output
$ old_default = f$environment("DEFAULT")
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
         f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ if f$search("build.dir") .eqs. "" then create/directory [.build]
$ say "vmsnotify probes, ", f$getsyi("NODENAME"), ", OpenVMS ", -
      f$getsyi("VERSION"), " ", f$getsyi("ARCH_NAME")
$ cc_base = "/STANDARD=C99/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES" + -
            "/INCLUDE_DIRECTORY=([.probes])"
$ built = ""
$ failed = ""
$ pname = "probe_position"
$ cc 'cc_base' /OBJECT=[.build]'pname'.obj [.probes]'pname'.c
$ sev = $severity
$ if sev .eq. 2 .or. sev .eq. 4 then goto fail
$ if sev .eq. 0 then say "  ''pname' compiled with warnings -- paste them"
$ link /EXECUTABLE=[.build]'pname'.exe [.build]'pname'.obj
$ if $severity .ne. 1 then goto fail
$ built = built + " " + pname
$ goto summary
$ fail:
$ failed = failed + " " + pname
$ if f$search("[.build]''pname'.exe") .nes. "" then -
      delete/nolog [.build]'pname'.exe;*
$ summary:
$ say "built: ''built'"
$ if failed .nes. "" then say "FAILED:''failed'"
$ set default 'old_default'
$ exit 1
