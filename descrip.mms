! descrip.mms : MMS description file for the vmsnotify agent
!
! Usage, from the vmsnotify directory:
!     $ MMS                build VMSNOTIFY.EXE, VMSNOTIFY_TLS.EXE and
!                         VMSNOTIFY_LAUNCH.EXE
!     $ MMS CLEAN          remove the agent's objects and images
!
! Type the target in capitals. With SET PROCESS/PARSE_STYLE=EXTENDED,
! DCL passes "clean" through in lower case, and MMS does not match it
! (%MMS-F-BADTARG, found with vmsotel's file).
!
! build_vms.com is the path to try first: it finds the OpenSSL kit and
! checks everything it does. This file builds the same images from the
! same flags. Not run yet on VMS.
!
! Keep it in step with build_vms.com and the Makefile: a source file
! added to one must be added to all three (tools/check_build_files.py).
!
! Comments use "!", and a hyphen as the last character of any line,
! comment included, continues it -- so no comment here ends in one.
!
! MMS cannot search for OpenSSL, so the kit is named here: SSL3, the
! 32-bit-pointer images. VN_EXPECT_OPENSSL_3 below makes tls.c refuse to
! compile if the headers OPENSSL selects are not 3.x. Change all three
! together. No VAX: it has neither OpenSSL nor /STANDARD=C99.

SSL_INCLUDE = SSL3$INCLUDE
SSL_LIBRARY = SYS$LIBRARY:SSL3$LIBSSL_SHR32
CRYPTO_LIBRARY = SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32
SSL_EXPECT = VN_EXPECT_OPENSSL_3

! PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES, or every POSIX name (socket,
! poll, getaddrinfo) is left a bare symbol that fails to link. No
! /POINTER_SIZE here: the system-service code's item lists need 32-bit
! pointers. Only tls.obj, which calls the ..._SHR32 images, states it.
! On Alpha add /FLOAT=IEEE_FLOAT: MMS/MACRO=FLOAT="/FLOAT=IEEE_FLOAT"

FLOAT =
IMAGES = [.build]vmsnotify.exe, [.build]vmsnotify_tls.exe,-
[.build]vmsnotify_launch.exe

INCLUDES = /INCLUDE_DIRECTORY=([.src.model],[.src.notify],[.src.platform],-
[.src.transport],[.src.sources],[.src.agent])
CFLAGS = /STANDARD=C99/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES$(FLOAT)$(INCLUDES)

OPT = [.build]vmsnotify_ssl.opt

CORE_OBJS = [.build]vn_types.obj,[.build]logparse.obj,[.build]rules.obj,-
[.build]throttle.obj,[.build]json.obj,[.build]format.obj,-
[.build]endpoint.obj,[.build]config.obj,[.build]queue.obj,-
[.build]vms_logs.obj,[.build]vms_sys.obj,[.build]platform_posix.obj

HEADERS = [.src.model]vn_types.h,[.src.model]version.h,-
[.src.model]logparse.h,[.src.model]rules.h,[.src.model]throttle.h,-
[.src.notify]json.h,[.src.notify]format.h,[.src.notify]endpoint.h,-
[.src.platform]platform.h,[.src.transport]http.h,-
[.src.transport]tls.h,[.src.transport]queue.h,-
[.src.sources]logsource.h,[.src.agent]config.h

! [.build] must exist before the first compile, and OPENSSL must name
! the kit: VSI C turns <openssl/ssl.h> into openssl:ssl.h, so that
! logical, not the include list, picks the headers. /JOB because MMS
! runs each action in a subprocess.

.FIRST
    @- IF F$SEARCH("BUILD.DIR;1") .EQS. "" THEN CREATE/DIRECTORY [.build]
    @ DEFINE/JOB/NOLOG OPENSSL $(SSL_INCLUDE):

! .LAST runs only when MMS succeeds; after a failed build, DEASSIGN/JOB
! OPENSSL by hand.

.LAST
    @- IF F$TRNLNM("OPENSSL","LNM$JOB") .NES. "" THEN DEASSIGN/JOB OPENSSL

ALL : $(IMAGES)
    @ WRITE SYS$OUTPUT "build complete: $(IMAGES)"

! ==== the agent's objects ====

[.build]vn_types.obj : [.src.model]vn_types.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.model]vn_types.c

[.build]logparse.obj : [.src.model]logparse.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.model]logparse.c

[.build]rules.obj : [.src.model]rules.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.model]rules.c

[.build]throttle.obj : [.src.model]throttle.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.model]throttle.c

[.build]json.obj : [.src.notify]json.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.notify]json.c

[.build]format.obj : [.src.notify]format.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.notify]format.c

[.build]endpoint.obj : [.src.notify]endpoint.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.notify]endpoint.c

[.build]config.obj : [.src.agent]config.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.agent]config.c

[.build]queue.obj : [.src.transport]queue.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.transport]queue.c

[.build]vms_logs.obj : [.src.sources.vms]vms_logs.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.sources.vms]vms_logs.c

[.build]vms_sys.obj : [.src.sources.vms]vms_sys.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.sources.vms]vms_sys.c

! _SOCKADDR_LEN selects the BSD 4.4 socket structures getaddrinfo needs.

[.build]platform_posix.obj : [.src.platform]platform_posix.c, $(HEADERS)
    $(CC)$(CFLAGS)/DEFINE=(_SOCKADDR_LEN)/OBJECT=$(MMS$TARGET) [.src.platform]platform_posix.c

[.build]http.obj : [.src.transport]http.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.transport]http.c

[.build]agent.obj : [.src.agent]agent.c, $(HEADERS)
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) [.src.agent]agent.c

! The TLS image's three: http.c and agent.c again with VN_WITH_TLS, and
! tls.c with the pointer size of the OpenSSL images.

[.build]http_tls.obj : [.src.transport]http.c, $(HEADERS)
    $(CC)$(CFLAGS)/DEFINE=(VN_WITH_TLS)/OBJECT=$(MMS$TARGET) -
[.src.transport]http.c

[.build]agent_tls.obj : [.src.agent]agent.c, $(HEADERS)
    $(CC)$(CFLAGS)/DEFINE=(VN_WITH_TLS)/OBJECT=$(MMS$TARGET) -
[.src.agent]agent.c

[.build]tls.obj : [.src.transport]tls.c, $(HEADERS)
    $(CC)$(CFLAGS)/POINTER_SIZE=32/DEFINE=(VN_WITH_TLS,$(SSL_EXPECT))-
/OBJECT=$(MMS$TARGET) [.src.transport]tls.c

! The kit's launcher (copied from vmsotel's): persona services, $CREPRC,
! and OpenSSL's generator, so the pointer size of the ..._SHR32 images.

[.build]launch.obj : [.src.launch]launch.c
    $(CC)$(CFLAGS)/POINTER_SIZE=32/OBJECT=$(MMS$TARGET) [.src.launch]launch.c

! ==== linker options ====

$(OPT) :
    @ OPEN/WRITE OPTF $(OPT)
    @ WRITE OPTF "$(SSL_LIBRARY)/SHAREABLE"
    @ WRITE OPTF "$(CRYPTO_LIBRARY)/SHAREABLE"
    @ CLOSE OPTF

! ==== images ====
!
! Each link is followed by a severity test: an undefined symbol is a
! warning to LINK, which writes the image anyway and leaves $SEVERITY
! at 0. %X10000002 is an error status, which stops MMS.

[.build]vmsnotify.exe : [.build]agent.obj, [.build]http.obj, $(CORE_OBJS)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]agent.obj,[.build]http.obj,-
$(CORE_OBJS)
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

[.build]vmsnotify_tls.exe : [.build]agent_tls.obj, [.build]http_tls.obj, -
[.build]tls.obj, $(CORE_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]agent_tls.obj,-
[.build]http_tls.obj,[.build]tls.obj,$(CORE_OBJS),$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

[.build]vmsnotify_launch.exe : [.build]launch.obj, $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]launch.obj,$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

! ==== housekeeping ====
!
! The agent's products only; the probes' objects and images in [.build]
! are left alone. No lower-case alias: see the note at the top.

CLEAN :
    @- IF F$SEARCH("[.build]vmsnotify*.exe") .NES. "" THEN DELETE/NOCONFIRM [.build]vmsnotify*.exe;*
    @- IF F$SEARCH("[.build]vmsnotify_ssl.opt") .NES. "" THEN DELETE/NOCONFIRM [.build]vmsnotify_ssl.opt;*
    @- IF F$SEARCH("[.build]vn_types.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]vn_types.obj;*
    @- IF F$SEARCH("[.build]logparse.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]logparse.obj;*
    @- IF F$SEARCH("[.build]rules.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]rules.obj;*
    @- IF F$SEARCH("[.build]throttle.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]throttle.obj;*
    @- IF F$SEARCH("[.build]json.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]json.obj;*
    @- IF F$SEARCH("[.build]format.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]format.obj;*
    @- IF F$SEARCH("[.build]endpoint.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]endpoint.obj;*
    @- IF F$SEARCH("[.build]config.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]config.obj;*
    @- IF F$SEARCH("[.build]queue.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]queue.obj;*
    @- IF F$SEARCH("[.build]vms_logs.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]vms_logs.obj;*
    @- IF F$SEARCH("[.build]vms_sys.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]vms_sys.obj;*
    @- IF F$SEARCH("[.build]platform_posix.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]platform_posix.obj;*
    @- IF F$SEARCH("[.build]http*.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]http*.obj;*
    @- IF F$SEARCH("[.build]agent*.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]agent*.obj;*
    @- IF F$SEARCH("[.build]launch.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]launch.obj;*
    @- IF F$SEARCH("[.build]tls.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]tls.obj;*
