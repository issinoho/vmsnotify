/*
 * vmsnotify tests: log records made by the real parsers, so the rules and
 * the formatter see what they will see on VMS. The packet layout is
 * NSADEF's (vmsotel tests/test_logs.c, findings 37).
 */

#ifndef VN_RECS_H
#define VN_RECS_H

#include <string.h>

#include "logparse.h"
#include "q.h"

static size_t recs_pkt(unsigned char *b, size_t at, unsigned type, const char *s)
{
    size_t n = strlen(s);

    b[at] = (unsigned char) ((n + 4) & 0xff);
    b[at + 1] = (unsigned char) ((n + 4) >> 8);
    b[at + 2] = (unsigned char) (type & 0xff);
    b[at + 3] = (unsigned char) (type >> 8);
    memcpy(b + at + 4, s, n);
    return at + 4 + n;
}

/* An audit record of NSA type `type` (5 LOGFAIL, 3 BREAKIN, 1 SERVER,
   10 SYSUAF, 6 LOGIN ...), with each non-NULL packet; at a fixed time,
   13-NOV-2026 16:44:37 UTC. */
static int recs_audit(vn_log_rec *r, unsigned type, const char *user,
                      const char *remote_user, const char *remote,
                      const char *terminal)
{
    unsigned char b[600];
    size_t at = 20;
    unsigned count = 0;
    /* VMS time for 2026-11-13 16:44:37.00 local (UTC): Unix 1794588277,
       (1794588277 + 3506716800) * 10^7. */
    const vn_u64 t = Q(0x00bc5716bb9b0880ULL);
    unsigned char ts[8];
    int i;

    for (i = 0; i < 4; i++) {
        ts[i] = (unsigned char) (vn_qlo(t) >> (8 * i));
        ts[i + 4] = (unsigned char) (vn_qhi(t) >> (8 * i));
    }
    b[at] = 12; b[at + 1] = 0; b[at + 2] = 50; b[at + 3] = 0;   /* TIME_STAMP */
    memcpy(b + at + 4, ts, 8);
    at += 12;
    count++;
    if (user)        { at = recs_pkt(b, at, 56, user); count++; }
    if (remote_user) { at = recs_pkt(b, at, 45, remote_user); count++; }
    if (remote)      { at = recs_pkt(b, at, 44, remote); count++; }
    if (terminal)    { at = recs_pkt(b, at, 49, terminal); count++; }
    memset(b, 0, 20);
    b[0] = (unsigned char) type;
    b[2] = 1;
    b[4] = 0x1c;
    b[6] = (unsigned char) count;
    b[8] = (unsigned char) (at & 0xff);
    b[9] = (unsigned char) (at >> 8);
    b[11] = 3;
    return vn_nsa_decode(b, at, 0, r);
}

/* An OPCOM message: a header at 13-NOV-2026 16:44:37.00, then the lines
   of text (separated by \n in text), through the real parser. */
static int recs_opcom(vn_log_rec *r, const char *text)
{
    vn_opcom_parser p;
    char line[400];
    const char *s = text;

    vn_opcom_init(&p, 0);
    vn_opcom_feed(&p, "%%%%%%%%%%%  OPCOM  13-NOV-2026 16:44:37.00  %%%%%%%%%%%", 54, r);
    while (*s) {
        const char *e = strchr(s, '\n');
        size_t n = e ? (size_t) (e - s) : strlen(s);

        memcpy(line, s, n);
        line[n] = '\0';
        vn_opcom_feed(&p, line, n, r);
        s += n + (e ? 1 : 0);
    }
    return vn_opcom_feed(&p, "", 0, r);
}

#endif
