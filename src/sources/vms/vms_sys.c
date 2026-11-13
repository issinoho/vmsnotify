/*
 * vmsnotify, from vmsotel's src/sources/vms/vms_source.c: the one thing the log reader needs from the system
 * besides RMS -- the time differential, since both logs keep local time.
 *
 * Built without /POINTER_SIZE: item lists assume 32-bit pointers.
 */

#include <stdlib.h>
#include <string.h>

#include <descrip.h>
#include <lnmdef.h>
#include <ctype.h>
#include <syidef.h>
#include <starlet.h>

#include "vn_types.h"

typedef struct {
    unsigned short len, code;
    void *buf;
    void *retlen;
} ile3;

int vn_vms_system_tdf(long *tdf, char *err, size_t errcap);
int vn_vms_node(char *buf, size_t cap);

/*
 * SYS$TIMEZONE_DIFFERENTIAL from the system table, seconds east of UTC.
 * Not getenv: on x86 a process-level definition changed what getenv saw
 * but not what time() returned (vmsotel's docs/findings.md), so one
 * stray logical would put every time out.
 */
int vn_vms_system_tdf(long *tdf, char *err, size_t errcap)
{
    static char table[] = "LNM$SYSTEM_TABLE";
    static char name[] = "SYS$TIMEZONE_DIFFERENTIAL";
    struct dsc$descriptor_s td, nd;
    unsigned int attr = LNM$M_CASE_BLIND;
    char value[64];
    unsigned short len = 0;
    ile3 ile[2];
    unsigned int st;

    td.dsc$w_length = (unsigned short) (sizeof table - 1);
    td.dsc$b_dtype = DSC$K_DTYPE_T;
    td.dsc$b_class = DSC$K_CLASS_S;
    td.dsc$a_pointer = table;
    nd = td;
    nd.dsc$w_length = (unsigned short) (sizeof name - 1);
    nd.dsc$a_pointer = name;
    memset(ile, 0, sizeof ile);
    ile[0].len = sizeof value - 1;
    ile[0].code = LNM$_STRING;
    ile[0].buf = value;
    ile[0].retlen = &len;
    st = sys$trnlnm(&attr, (void *) &td, (void *) &nd, 0, (void *) ile);
    if (!(st & 1)) {
        vn_snprintf(err, errcap, "SYS$TIMEZONE_DIFFERENTIAL is not defined "
                    "in LNM$SYSTEM_TABLE (status %%X%08X); without it local "
                    "time cannot be turned into UTC", st);
        return 0;
    }
    value[len] = '\0';
    *tdf = strtol(value, NULL, 10);
    return 1;
}

/*
 * The SCS node name, $GETSYIW SYI$_NODENAME: what SHOW SYSTEM and the
 * operator log call this system, and what the TCP/IP host name can
 * differ from. platform_posix.c's vn_platform_node() calls this on VMS.
 * Upper case, trailing blanks dropped. 1, or 0 with buf empty if the
 * system gives none (the caller then falls back to the host name).
 *
 * The item list is item_list_3, so 32-bit pointers; the return length
 * is a word here, as item_list_3 declares (it is $GETRMI that writes a
 * longword). The status is the call's and the I/O status block's both.
 */
int vn_vms_node(char *buf, size_t cap)
{
    char name[32];
    unsigned short len = 0;
    unsigned short iosb[4];
    ile3 ile[2];
    unsigned int st;
    size_t i;

    if (cap == 0)
        return 0;
    buf[0] = '\0';
    memset(ile, 0, sizeof ile);
    memset(iosb, 0, sizeof iosb);
    ile[0].len = (unsigned short) (sizeof name - 1);
    ile[0].code = SYI$_NODENAME;
    ile[0].buf = name;
    ile[0].retlen = &len;
    st = sys$getsyiw(0, 0, 0, (void *) ile, (void *) iosb, 0, 0);
    if (!(st & 1) || !(iosb[0] & 1))
        return 0;
    if (len > sizeof name - 1)
        len = (unsigned short) (sizeof name - 1);
    while (len > 0 && (name[len - 1] == ' ' || name[len - 1] == '\0'))
        len--;
    for (i = 0; i < len && i + 1 < cap; i++)
        buf[i] = (char) toupper((unsigned char) name[i]);
    buf[i] = '\0';
    return i > 0;
}
