/*
 * vmsnotify: turning records into messages.
 *
 * A message is what every endpoint sends, in its own encoding: a title,
 * a plain-text body, a priority, and the record it came from when there
 * is one (the webhook sends all its fields). Three kinds:
 *   - an event: a record a rule matched;
 *   - a summary: events a throttle counted ("12 more ...");
 *   - a notice: the agent's own news (started, cannot read a log).
 * Text is kept as the logs have it (8-bit); the encoders make it UTF-8.
 *
 * Pure: no I/O.
 */

#ifndef VN_FORMAT_H
#define VN_FORMAT_H

#include <stddef.h>

#include "logparse.h"
#include "rules.h"
#include "throttle.h"

#define VN_MSG_TITLE 240
#define VN_MSG_BODY  (VN_LOG_BODY + 640)

enum { VN_MSG_EVENT = 1, VN_MSG_SUMMARY = 2, VN_MSG_NOTICE = 3 };

typedef struct {
    int kind;                   /* VN_MSG_* */
    char node[32];              /* SCS node name, e.g. X86VMS */
    char title[VN_MSG_TITLE];
    char body[VN_MSG_BODY];
    int priority;               /* VN_PRIO_* */
    char rule[VN_RULE_NAME];    /* the rule's name; "" for a notice */
    char to[VN_RULE_LIST];      /* endpoint names; "" for all */
    const vn_log_rec *rec;      /* for an event; NULL otherwise */
    unsigned long count;        /* for a summary */
    long window_s;              /* for a summary */
} vn_msg;

void vn_format_event(vn_msg *m, const char *node, const vn_rule *r,
                     const vn_log_rec *rec);
void vn_format_summary(vn_msg *m, const char *node, const vn_summary *s);
void vn_format_notice(vn_msg *m, const char *node, int priority,
                      const char *title, const char *body);

/* The record's time, "2026-11-13 16:44:37 UTC"; "time unknown" for 0. */
void vn_format_time(const vn_log_rec *rec, char *out, size_t cap);

/* The headline of a record, without the node: the audit sentence, or
   the OPCOM message's first line of text ("Request 3: MOUNT TAPE..."). */
void vn_headline(const vn_log_rec *rec, char *out, size_t cap);

#endif
