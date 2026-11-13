/*
 * vmsnotify: the configuration file.
 *
 * vmsotel's syntax -- lines of `key = value`, # or ! starting a comment
 * line, keys lower-case, values trimmed -- with named sections:
 *
 *     logs.opcom = yes
 *     logs.audit = yes
 *
 *     [endpoint home]
 *     type       = gotify
 *     url        = https://gotify.lan
 *     token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN
 *
 *     [rule monitor-noise]
 *     source = audit
 *     types  = LOGFAIL
 *     remote = *192.168.0.131
 *     action = ignore
 *
 * Settings before the first section are global. A [rule] is checked in
 * the order written, before the built-in defaults (rules.defaults = no
 * leaves them out). vmsnotify.conf.example documents every key.
 *
 * Pure: vn_config_parse takes the file's text. Token files are read by
 * the agent, which knows the platform.
 */

#ifndef VN_CONFIG_H
#define VN_CONFIG_H

#include <stddef.h>

#include "endpoint.h"
#include "rules.h"

#define VN_ENDPOINTS_MAX 8
#define VN_CONFIG_STR    256

typedef struct {
    /* Global. */
    int opcom;                          /* logs.opcom, default yes */
    int audit;                          /* logs.audit, default yes */
    char opcom_file[VN_CONFIG_STR];
    char audit_file[VN_CONFIG_STR];
    char node[32];                      /* node name in titles; "" = the system's */
    int defaults;                       /* rules.defaults, default yes */
    char defaults_to[VN_RULE_LIST];     /* rules.defaults.to */
    long defaults_throttle_s;           /* rules.defaults.throttle; -1 unset */
    unsigned interval_s;                /* poll the logs every n s, default 10 */
    unsigned catchup_max_age_s;         /* catchup.max_age, default 3600 */
    unsigned catchup_max_records;       /* catchup.max_records, default 500 */
    int notices;                        /* the agent's own notices, default yes */
    unsigned queue_len;                 /* messages kept per endpoint, default 32 */

    size_t nendpoints;
    vn_endpoint endpoint[VN_ENDPOINTS_MAX];
    char token_file[VN_ENDPOINTS_MAX][VN_CONFIG_STR];   /* by endpoint */

    vn_ruleset rules;                   /* the user's, then the defaults */
} vn_config;

/* Parses text (n bytes) into c. 1 on success; 0 with the first problem,
   "line 12: ...", in err. */
int vn_config_parse(vn_config *c, const char *text, size_t n,
                    char *err, size_t errcap);

/* The endpoint named name, or NULL. */
const vn_endpoint *vn_config_endpoint(const vn_config *c, const char *name);

#endif
