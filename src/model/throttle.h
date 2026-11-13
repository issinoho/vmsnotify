/*
 * vmsnotify: throttling, so a burst becomes a message and a summary.
 *
 * Events are grouped by rule and key (the key is the record's user and
 * remote node: vn_throttle_key). The first event of a group is sent at
 * once and opens a window of the rule's throttle_s seconds. Events of the
 * group inside the window are counted, not sent. When the window ends
 * with any counted, one summary is due: "12 more ... in 300 s". The next
 * event after that opens a new window. A break-in storm of two hundred
 * attempts therefore gives two messages, not two hundred.
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
    vn_thr_entry e[VN_THR_MAX];
    size_t npending;
    vn_summary pending[VN_THR_MAX];     /* due, not yet collected */
} vn_throttle;

void vn_throttle_init(vn_throttle *t);

/* The group key for rec: "user from remote", either part possibly empty. */
void vn_throttle_key(const vn_log_rec *rec, char *key, size_t cap);

/* 1: send this event now. 0: it was counted in an open window. label is
   kept for the summary. */
int vn_throttle_admit(vn_throttle *t, const vn_rule *r, const char *key,
                      const char *label, unsigned long now_s);

/* Copies up to max summaries that are due at now_s -- windows that have
   ended with events counted -- into out, and forgets them. Windows that
   ended with none counted are freed quietly. Returns how many. With
   flush set, every open window counts as ended (at shutdown). */
size_t vn_throttle_due(vn_throttle *t, unsigned long now_s, int flush,
                       vn_summary *out, size_t max);

#endif
