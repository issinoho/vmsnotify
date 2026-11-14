/*
 * vmsnotify: rules -- which log records become notifications.
 *
 * A rule matches on the record's source, audit type, severity, user,
 * terminal, remote node and text, and says what to do with a match:
 * notify, at a priority, to some or all endpoints, throttled; or ignore.
 * The first rule that matches decides. The user's rules come first, then
 * the built-in defaults (vn_rules_add_defaults), which notify on security
 * events and problems and leave everything else quiet. A record no rule
 * matches is not sent.
 *
 * Pure: no I/O, so all of it is tested on Linux.
 */

#ifndef VN_RULES_H
#define VN_RULES_H

#include <stddef.h>

#include "logparse.h"

#define VN_RULES_MAX   48
#define VN_RULE_NAME   32
#define VN_RULE_PAT    128
#define VN_RULE_LIST   160

enum { VN_ACT_NOTIFY = 1, VN_ACT_IGNORE = 2 };

/* Priorities, low to high. Each endpoint maps them to its own scale. */
enum { VN_PRIO_LOW = 1, VN_PRIO_NORMAL = 2, VN_PRIO_HIGH = 3, VN_PRIO_URGENT = 4 };

typedef struct {
    char name[VN_RULE_NAME];
    int builtin;                /* one of vn_rules_add_defaults' */

    /* What it matches; an empty pattern or 0 matches anything. */
    int source;                 /* VN_LOG_OPCOM, VN_LOG_AUDIT, or 0 */
    char types[VN_RULE_LIST];   /* audit types, comma-separated: LOGFAIL,BREAKIN */
    int min_severity;           /* VN_SEV_WARN ...; 0 for any */
    int request;                /* 1: only operator REQUESTs */
    char user[VN_RULE_PAT];     /* VMS wildcards (* and %), case-blind */
    char terminal[VN_RULE_PAT];
    char remote[VN_RULE_PAT];   /* remote node name or address */
    char text[VN_RULE_PAT];     /* the whole message text */
    char not_user[VN_RULE_LIST]; /* user patterns, comma-separated, that
                                   keep the rule from matching */

    /* What it does. */
    int action;                 /* VN_ACT_* */
    int priority;               /* VN_PRIO_* */
    char to[VN_RULE_LIST];      /* endpoint names, comma-separated; "" all */
    long throttle_s;            /* repeats within this many seconds are
                                   counted and summarised; 0 sends each */
} vn_rule;

typedef struct {
    size_t n;
    vn_rule rule[VN_RULES_MAX];
} vn_ruleset;

#define VN_THROTTLE_DEFAULT 300

/* A rule with every field at its default: matches everything, notifies
   at normal priority to all endpoints, throttled 300 s. */
void vn_rule_init(vn_rule *r, const char *name);

/* Appends a copy of r. 0 if the set is full. */
int vn_rules_add(vn_ruleset *rs, const vn_rule *r);

/* Appends the built-in defaults (docs/design.md, "Default rules"). 0 if
   the set is full. */
int vn_rules_add_defaults(vn_ruleset *rs);

/* The first rule that matches rec, or NULL. */
const vn_rule *vn_rules_match(const vn_ruleset *rs, const vn_log_rec *rec);

/* 1 if rule r matches rec. */
int vn_rule_matches(const vn_rule *r, const vn_log_rec *rec);

/* 1 if endpoint name is among r->to (or r->to is empty). Case-blind. */
int vn_rule_sends_to(const vn_rule *r, const char *endpoint);

/* VMS wildcard match, * and %, case-blind: 1 if pattern p matches t. */
int vn_wildcard_match(const char *p, const char *t);

/* A string attribute's value, or NULL. */
const char *vn_attr(const vn_log_rec *rec, const char *key);

/* The record's user, terminal and remote node, from whichever attribute
   holds each for its source; "" when it has none. */
const char *vn_rec_user(const vn_log_rec *rec);
const char *vn_rec_terminal(const vn_log_rec *rec);
const char *vn_rec_remote(const vn_log_rec *rec);

/* "low", "normal", "high", "urgent"; and back (0 if unknown). */
const char *vn_prio_name(int prio);
int vn_prio_parse(const char *s);

#endif
