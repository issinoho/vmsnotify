/*
 * vmsnotify: throttling, so a burst becomes a message and a summary.
 *
 * Events are grouped by rule and key (the key says who tried, from where:
 * vn_throttle_key). The first event of a group is sent at
 * once and opens a window of the rule's throttle_s seconds. Events of the
 * group inside the window are counted, not sent. When the window ends
 * with any counted, one summary is due: "12 more ... in 300 s". The next
 * event after that opens a new window. A break-in storm of two hundred
 * attempts therefore gives two messages, not two hundred.
 *
 * Twins: one failed SSH login on Alpha writes two audit records in the same
 * second, as different users but the same person and place. An event with
 * the rule and key of one just admitted (sent, or counted in a window),
 * whose record time is within VN_THR_TWIN_S seconds of that one's, is a
 * duplicate of it: not sent and not counted, so it makes no summary
 * either. This holds when the rule's throttle is 0 too: the memory is a
 * short list of recent events, not the windows.
 *
 * Nothing is lost: when the table is full, an event that has no group is
 * sent rather than suppressed.
 *
 * Pure; times are seconds from any clock that does not go back (the
 * agent passes vn_monotonic seconds).
 */

#ifndef VN_THROTTLE_H
#define VN_THROTTLE_H

#include <stddef.h>

#include "rules.h"

#define VN_THR_MAX    64
#define VN_THR_KEY    160
#define VN_THR_LABEL  240
#define VN_THR_TWIN_S 2         /* record times this close are one event */
#define VN_THR_RECENT 32        /* events remembered for twins */

/* What vn_throttle_admit says. */
#define VN_THR_COUNTED 0
#define VN_THR_SEND    1
#define VN_THR_DUP     2

typedef struct {
    char rule[VN_RULE_NAME];
    char key[VN_THR_KEY];
    char label[VN_THR_LABEL];   /* the first event's title */
    char to[VN_RULE_LIST];      /* the rule's endpoints */
    int priority;
    unsigned long count;        /* events counted, not sent */
    long window_s;
} vn_summary;

typedef struct {
    int used;
    unsigned long window_end;
    vn_summary s;
} vn_thr_entry;

typedef struct {
    char rule[VN_RULE_NAME];
    char key[VN_THR_KEY];
    unsigned long rec_s;        /* record time; 0 = slot unused */
} vn_thr_recent;

typedef struct {
    vn_thr_entry e[VN_THR_MAX];
    vn_thr_recent recent[VN_THR_RECENT];
    size_t next_recent;
    size_t npending;
    vn_summary pending[VN_THR_MAX];     /* due, not yet collected */
} vn_throttle;

void vn_throttle_init(vn_throttle *t);

/* The group key for rec: "PERSON from PLACE", either part possibly empty.
   The person is the record's remote user if it has one, else its user,
   upper-cased; the place is its remote node without a leading service
   prefix (vn_throttle_place). */
void vn_throttle_key(const vn_log_rec *rec, char *key, size_t cap);

/* The remote node without a service prefix: a leading run of [A-Za-z_$]
   and a colon, with at least one character that is not a hex digit
   ("SSH_PASSWORD:192.168.0.131" gives "192.168.0.131"). "FTP_C0A80083",
   "192.168.0.5" and IPv6 addresses ("fe80::1", "abcd::1") have none and
   are returned as they are. Returns a pointer into remote. */
const char *vn_throttle_place(const char *remote);

/* The record's time in seconds for vn_throttle_admit; 0 when it is
   unknown, or when the record names no remote node (an operator message,
   a local audit event: two in one second are two events, not twins). */
unsigned long vn_throttle_rec_s(const vn_log_rec *rec);

/* VN_THR_SEND: send this event now. VN_THR_COUNTED: it was counted in an
   open window. VN_THR_DUP: a twin of an event just sent, dropped and not
   counted. label is kept for the summary. now_s is the clock for windows;
   rec_s is the record's time (vn_throttle_rec_s), 0 if unknown, which is
   never a twin. */
int vn_throttle_admit(vn_throttle *t, const vn_rule *r, const char *key,
                      const char *label, unsigned long now_s,
                      unsigned long rec_s);

/* Copies up to max summaries that are due at now_s -- windows that have
   ended with events counted -- into out, and forgets them. Windows that
   ended with none counted are freed quietly. Returns how many. With
   flush set, every open window counts as ended (at shutdown). */
size_t vn_throttle_due(vn_throttle *t, unsigned long now_s, int flush,
                       vn_summary *out, size_t max);

#endif
