/*
 * vmsnotify, from vmsotel's src/model/logparse.h: log records, and the two parsers that make them (phase 3).
 *
 * The operator log is text records: a header line
 *     %%%%%%%%%%%  OPCOM   1-NOV-2026 09:53:17.66  %%%%%%%%%%%
 * then the message's lines, with an empty record before the next
 * header (vmsotel findings 34). The audit journal is binary records in
 * NSADEF's NSAMSGDEF layout: a 20-byte header, then packets of word
 * size (header included), word type, data (vmsotel findings 37).
 *
 * Both parsers are pure: they take records the source has read and
 * fill vn_log_rec, so all of it is tested on Linux. Times in both files
 * are VMS local time; tdf_s is the time differential to subtract,
 * seconds east of UTC, as SYS$TIMEZONE_DIFFERENTIAL gives it.
 */

#ifndef VN_LOGPARSE_H
#define VN_LOGPARSE_H

#include <stddef.h>

#include "vn_types.h"

#define VN_LOG_BODY   2048      /* longer bodies end in "..." */
#define VN_LOG_ATTRS  14
#define VN_LOG_VAL    128

enum { VN_LOG_OPCOM = 1, VN_LOG_AUDIT = 2 };

/* OTLP SeverityNumber values used here. */
enum {
    VN_SEV_INFO = 9,
    VN_SEV_WARN = 13,
    VN_SEV_ERROR = 17,
    VN_SEV_FATAL = 21
};

typedef struct {
    const char *key;            /* a string constant */
    int is_int;
    unsigned long ival;         /* a PID, a request number, a code */
    char sval[VN_LOG_VAL];
} vn_log_attr;

typedef struct {
    int source;                 /* VN_LOG_OPCOM or VN_LOG_AUDIT */
    vn_u64 time_ns;             /* when it happened, Unix ns; 0 unknown */
    int severity;               /* VN_SEV_* */
    const char *severity_text;  /* "INFO", ... */
    const char *file;           /* the file it came from; the source sets it */
    char body[VN_LOG_BODY];
    size_t nattrs;
    vn_log_attr attrs[VN_LOG_ATTRS];
} vn_log_rec;

/* VMS binary time (100 ns since 17-Nov-1858, local) to Unix ns, UTC. 0
   for a time before 1970. */
vn_u64 vn_vms_time_to_unix_ns(vn_u64 vms_time, long tdf_s);

/* ---- the operator log ---------------------------------------------- */

typedef struct {
    long tdf_s;
    int in_msg;                 /* a header has been seen */
    vn_log_rec rec;             /* the message being gathered */
    size_t body_len;
    size_t lines;
    int truncated;
} vn_opcom_parser;

void vn_opcom_init(vn_opcom_parser *p, long tdf_s);

/*
 * Feeds one record of the log. A header or an empty record ends the
 * message being gathered: then it is copied to out and 1 is returned.
 * A header also starts the next one. Lines before the first header are
 * not part of any message and are ignored.
 */
int vn_opcom_feed(vn_opcom_parser *p, const char *line, size_t len,
                  vn_log_rec *out);

/* The message being gathered, if any, as far as it goes: 1 and out
   filled, or 0. The parser is left as it was. */
int vn_opcom_pending(const vn_opcom_parser *p, vn_log_rec *out);

/* Lines in the message being gathered (0 with none), so a reader can
   tell whether it grew between two looks. */
size_t vn_opcom_pending_lines(const vn_opcom_parser *p);

/* 1 if line is an OPCOM header. */
int vn_opcom_is_header(const char *line, size_t len);

/* ---- the audit journal --------------------------------------------- */

/*
 * Decodes one journal record into out. 1 on success; 0 if it does not
 * fit NSAMSGDEF (sizes that do not add up), with out unusable.
 *
 * The breakin password packet (NSA$C_PKT_PASSWORD) and the command line
 * are never copied out: either can hold a password someone typed.
 */
int vn_nsa_decode(const unsigned char *b, size_t len, long tdf_s,
                  vn_log_rec *out);

/* "LOGFAIL" for NSA$C_MSG_LOGFAIL (5), ...; NULL for an unknown type. */
const char *vn_nsa_type_name(unsigned type);

#endif
