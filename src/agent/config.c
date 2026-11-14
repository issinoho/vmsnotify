/*
 * vmsnotify: the configuration file. See config.h.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "vn_types.h"

#define LINE_MAX_ 512

enum { SEC_GLOBAL, SEC_ENDPOINT, SEC_RULE };

static void defaults(vn_config *c)
{
    memset(c, 0, sizeof *c);
    c->opcom = 1;
    c->audit = 1;
    strcpy(c->opcom_file, "SYS$MANAGER:OPERATOR.LOG");
    strcpy(c->audit_file, "SYS$MANAGER:SECURITY.AUDIT$JOURNAL");
    c->defaults = 1;
    c->defaults_throttle_s = -1;
    c->interval_s = 10;
    c->catchup_max_age_s = 3600;
    c->catchup_max_records = 500;
    c->notices = 1;
    c->queue_len = 32;
}

static int ieq(const char *a, const char *b)
{
    while (*a && *b && tolower((unsigned char) *a) == tolower((unsigned char) *b)) {
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* yes/true/on/1 or no/false/off/0; -1 otherwise. */
static int boolean(const char *v)
{
    if (ieq(v, "yes") || ieq(v, "true") || ieq(v, "on") || strcmp(v, "1") == 0)
        return 1;
    if (ieq(v, "no") || ieq(v, "false") || ieq(v, "off") || strcmp(v, "0") == 0)
        return 0;
    return -1;
}

/* A whole number from lo to hi; 0 if v is not one. */
static int number(const char *v, unsigned long lo, unsigned long hi, unsigned long *out)
{
    char *end;
    unsigned long n;

    if (!isdigit((unsigned char) v[0]))
        return 0;
    n = strtoul(v, &end, 10);
    if (*end != '\0' || n < lo || n > hi)
        return 0;
    *out = n;
    return 1;
}

static int set(char *dst, size_t cap, const char *v)
{
    size_t n = strlen(v);

    if (n >= cap)
        return 0;
    memcpy(dst, v, n + 1);
    return 1;
}

static int severity(const char *v)
{
    if (ieq(v, "warning") || ieq(v, "warn") || ieq(v, "w"))
        return VN_SEV_WARN;
    if (ieq(v, "error") || ieq(v, "e"))
        return VN_SEV_ERROR;
    if (ieq(v, "fatal") || ieq(v, "severe") || ieq(v, "f"))
        return VN_SEV_FATAL;
    return 0;
}

#define FAIL(...) do { vn_snprintf(err, errcap, __VA_ARGS__); return 0; } while (0)

static int global(vn_config *c, const char *k, const char *v, char *err, size_t errcap)
{
    unsigned long n;
    int b;

    if (strcmp(k, "logs.opcom") == 0 || strcmp(k, "logs.audit") == 0 ||
        strcmp(k, "rules.defaults") == 0 || strcmp(k, "notices") == 0) {
        if ((b = boolean(v)) < 0)
            FAIL("%s must be yes or no", k);
        if (k[5] == 'o')
            c->opcom = b;
        else if (k[5] == 'a')
            c->audit = b;
        else if (k[0] == 'r')
            c->defaults = b;
        else
            c->notices = b;
    } else if (strcmp(k, "logs.opcom_file") == 0) {
        if (!set(c->opcom_file, sizeof c->opcom_file, v))
            FAIL("%s is too long", k);
    } else if (strcmp(k, "logs.audit_file") == 0) {
        if (!set(c->audit_file, sizeof c->audit_file, v))
            FAIL("%s is too long", k);
    } else if (strcmp(k, "node") == 0) {
        if (!set(c->node, sizeof c->node, v))
            FAIL("node is too long");
    } else if (strcmp(k, "rules.defaults.to") == 0) {
        if (!set(c->defaults_to, sizeof c->defaults_to, v))
            FAIL("%s is too long", k);
    } else if (strcmp(k, "rules.defaults.throttle") == 0) {
        if (!number(v, 0, 86400, &n))
            FAIL("%s must be 0 to 86400 seconds", k);
        c->defaults_throttle_s = (long) n;
    } else if (strcmp(k, "interval") == 0) {
        if (!number(v, 1, 3600, &n))
            FAIL("interval must be 1 to 3600 seconds");
        c->interval_s = (unsigned) n;
    } else if (strcmp(k, "catchup.max_age") == 0) {
        if (!number(v, 0, 604800, &n))
            FAIL("%s must be 0 to 604800 seconds", k);
        c->catchup_max_age_s = (unsigned) n;
    } else if (strcmp(k, "catchup.max_records") == 0) {
        if (!number(v, 0, 100000, &n))
            FAIL("%s must be 0 to 100000", k);
        c->catchup_max_records = (unsigned) n;
    } else if (strcmp(k, "queue") == 0) {
        if (!number(v, 1, 64, &n))
            FAIL("queue must be 1 to 64");
        c->queue_len = (unsigned) n;
    } else {
        FAIL("unknown setting %s", k);
    }
    return 1;
}

static int endpoint_key(vn_config *c, vn_endpoint *e, const char *k, const char *v,
                        char *err, size_t errcap)
{
    unsigned long n;
    char why[120];

    if (strcmp(k, "type") == 0) {
        if (!vn_endpoint_set_type(e, v))
            FAIL("type must be gotify, apprise, ntfy or webhook");
    } else if (strcmp(k, "url") == 0) {
        if (!vn_endpoint_set_url(e, v, why, sizeof why))
            FAIL("%s", why);
    } else if (strcmp(k, "token") == 0) {
        if (!set(e->token, sizeof e->token, v))
            FAIL("token is too long");
    } else if (strcmp(k, "token_file") == 0) {
        if (!set(c->token_file[c->nendpoints - 1], VN_CONFIG_STR, v))
            FAIL("token_file is too long");
    } else if (strcmp(k, "user") == 0) {
        if (!set(e->user, sizeof e->user, v))
            FAIL("user is too long");
    } else if (strcmp(k, "password") == 0) {
        if (!set(e->pass, sizeof e->pass, v))
            FAIL("password is too long");
    } else if (strcmp(k, "key") == 0) {
        if (!set(e->key, sizeof e->key, v))
            FAIL("key is too long");
    } else if (strcmp(k, "tag") == 0) {
        if (!set(e->tag, sizeof e->tag, v))
            FAIL("tag is too long");
    } else if (strcmp(k, "topic") == 0) {
        if (!set(e->topic, sizeof e->topic, v))
            FAIL("topic is too long");
    } else if (strcmp(k, "cafile") == 0) {
        if (!set(e->cafile, sizeof e->cafile, v))
            FAIL("cafile is too long");
    } else if (strcmp(k, "min_priority") == 0) {
        if ((e->min_priority = vn_prio_parse(v)) == 0)
            FAIL("min_priority must be low, normal, high or urgent");
    } else if (strcmp(k, "timeout") == 0) {
        if (!number(v, 1, 300, &n))
            FAIL("timeout must be 1 to 300 seconds");
        e->timeout_s = (unsigned) n;
    } else {
        FAIL("unknown endpoint setting %s", k);
    }
    return 1;
}

static int rule_key(vn_rule *r, const char *k, const char *v, char *err, size_t errcap)
{
    unsigned long n;
    int b;

    if (strcmp(k, "source") == 0) {
        if (ieq(v, "audit"))
            r->source = VN_LOG_AUDIT;
        else if (ieq(v, "opcom"))
            r->source = VN_LOG_OPCOM;
        else if (ieq(v, "any"))
            r->source = 0;
        else
            FAIL("source must be audit, opcom or any");
    } else if (strcmp(k, "types") == 0) {
        if (!set(r->types, sizeof r->types, v))
            FAIL("types is too long");
    } else if (strcmp(k, "severity") == 0) {
        if ((r->min_severity = severity(v)) == 0)
            FAIL("severity must be warning, error or fatal");
    } else if (strcmp(k, "request") == 0) {
        if ((b = boolean(v)) < 0)
            FAIL("request must be yes or no");
        r->request = b;
    } else if (strcmp(k, "user") == 0) {
        if (!set(r->user, sizeof r->user, v))
            FAIL("user is too long");
    } else if (strcmp(k, "terminal") == 0) {
        if (!set(r->terminal, sizeof r->terminal, v))
            FAIL("terminal is too long");
    } else if (strcmp(k, "remote") == 0) {
        if (!set(r->remote, sizeof r->remote, v))
            FAIL("remote is too long");
    } else if (strcmp(k, "not_user") == 0) {
        if (!set(r->not_user, sizeof r->not_user, v))
            FAIL("not_user is too long");
    } else if (strcmp(k, "text") == 0) {
        if (!set(r->text, sizeof r->text, v))
            FAIL("text is too long");
    } else if (strcmp(k, "action") == 0) {
        if (ieq(v, "notify"))
            r->action = VN_ACT_NOTIFY;
        else if (ieq(v, "ignore"))
            r->action = VN_ACT_IGNORE;
        else
            FAIL("action must be notify or ignore");
    } else if (strcmp(k, "priority") == 0) {
        if ((r->priority = vn_prio_parse(v)) == 0)
            FAIL("priority must be low, normal, high or urgent");
    } else if (strcmp(k, "to") == 0) {
        if (!set(r->to, sizeof r->to, v))
            FAIL("to is too long");
    } else if (strcmp(k, "throttle") == 0) {
        if (!number(v, 0, 86400, &n))
            FAIL("throttle must be 0 to 86400 seconds");
        r->throttle_s = (long) n;
    } else {
        FAIL("unknown rule setting %s", k);
    }
    return 1;
}

/* Every name in a `to` list must be an endpoint's. */
static int check_to(const vn_config *c, const char *list, char *bad, size_t cap)
{
    const char *p = list;

    while (*p) {
        const char *e;
        size_t n;
        char name[VN_EP_NAME];

        while (*p == ' ' || *p == ',')
            p++;
        e = p;
        while (*e && *e != ',')
            e++;
        n = (size_t) (e - p);
        while (n > 0 && p[n - 1] == ' ')
            n--;
        if (n > 0) {
            if (n >= sizeof name)
                n = sizeof name - 1;
            memcpy(name, p, n);
            name[n] = '\0';
            if (vn_config_endpoint(c, name) == NULL) {
                vn_snprintf(bad, cap, "%s", name);
                return 0;
            }
        }
        p = e;
    }
    return 1;
}

const vn_endpoint *vn_config_endpoint(const vn_config *c, const char *name)
{
    size_t i;

    for (i = 0; i < c->nendpoints; i++)
        if (ieq(c->endpoint[i].name, name))
            return &c->endpoint[i];
    return NULL;
}

int vn_config_parse(vn_config *c, const char *text, size_t n,
                    char *err, size_t errcap)
{
    size_t pos = 0, i;
    unsigned lineno = 0;
    int sec = SEC_GLOBAL;
    vn_rule *rule = NULL;
    vn_endpoint *ep = NULL;
    char why[160];

    defaults(c);
    err[0] = '\0';
    while (pos < n) {
        char line[LINE_MAX_], *k, *v, *eq, *end;
        size_t len = 0;

        lineno++;
        while (pos < n && text[pos] != '\n') {
            if (len + 1 < sizeof line)
                line[len++] = text[pos];
            else {
                vn_snprintf(err, errcap, "line %u: longer than %d characters",
                            lineno, LINE_MAX_ - 1);
                return 0;
            }
            pos++;
        }
        pos++;
        line[len] = '\0';
        k = line;
        while (isspace((unsigned char) *k))
            k++;
        end = k + strlen(k);
        while (end > k && isspace((unsigned char) end[-1]))
            *--end = '\0';
        if (*k == '\0' || *k == '#' || *k == '!')
            continue;

        if (*k == '[') {
            char *name;

            if (end[-1] != ']') {
                vn_snprintf(err, errcap, "line %u: a section is [endpoint NAME] or [rule NAME]", lineno);
                return 0;
            }
            end[-1] = '\0';
            k++;
            while (*k == ' ')
                k++;
            name = k;
            while (*name && *name != ' ')
                name++;
            if (*name == ' ')
                *name++ = '\0';
            while (*name == ' ')
                name++;
            v = name + strlen(name);
            while (v > name && v[-1] == ' ')
                *--v = '\0';
            if (*name == '\0' || strlen(name) >= VN_EP_NAME || strchr(name, ' ') || strchr(name, ',')) {
                vn_snprintf(err, errcap, "line %u: a section needs a name of one word, under %d characters",
                            lineno, VN_EP_NAME);
                return 0;
            }
            if (strcmp(k, "endpoint") == 0) {
                if (c->nendpoints >= VN_ENDPOINTS_MAX) {
                    vn_snprintf(err, errcap, "line %u: at most %d endpoints", lineno, VN_ENDPOINTS_MAX);
                    return 0;
                }
                if (vn_config_endpoint(c, name) != NULL) {
                    vn_snprintf(err, errcap, "line %u: a second endpoint %s", lineno, name);
                    return 0;
                }
                ep = &c->endpoint[c->nendpoints++];
                memset(ep, 0, sizeof *ep);
                strcpy(ep->name, name);
                ep->timeout_s = 10;
                sec = SEC_ENDPOINT;
            } else if (strcmp(k, "rule") == 0) {
                vn_rule r;

                vn_rule_init(&r, name);
                if (!vn_rules_add(&c->rules, &r)) {
                    vn_snprintf(err, errcap, "line %u: too many rules", lineno);
                    return 0;
                }
                rule = &c->rules.rule[c->rules.n - 1];
                sec = SEC_RULE;
            } else {
                vn_snprintf(err, errcap, "line %u: unknown section [%s]", lineno, k);
                return 0;
            }
            continue;
        }

        eq = strchr(k, '=');
        if (eq == NULL) {
            vn_snprintf(err, errcap, "line %u: expected key = value", lineno);
            return 0;
        }
        v = eq + 1;
        while (eq > k && isspace((unsigned char) eq[-1]))
            eq--;
        *eq = '\0';
        while (isspace((unsigned char) *v))
            v++;
        if (*k == '\0' || *v == '\0') {
            vn_snprintf(err, errcap, "line %u: %s has no value", lineno, *k ? k : "(nothing)");
            return 0;
        }
        for (end = k; *end; end++)
            *end = (char) tolower((unsigned char) *end);

        why[0] = '\0';
        if (!(sec == SEC_GLOBAL ? global(c, k, v, why, sizeof why) :
              sec == SEC_ENDPOINT ? endpoint_key(c, ep, k, v, why, sizeof why) :
              rule_key(rule, k, v, why, sizeof why))) {
            vn_snprintf(err, errcap, "line %u: %s", lineno, why);
            return 0;
        }
    }

    /* Whole-file checks. */
    for (i = 0; i < c->nendpoints; i++) {
        vn_endpoint *e = &c->endpoint[i];
        int had_file = c->token_file[i][0] != '\0';

        if (had_file && e->token[0] != '\0') {
            vn_snprintf(err, errcap, "endpoint %s: token and token_file both given", e->name);
            return 0;
        }
        if (had_file)
            strcpy(e->token, "(from token_file)");     /* for the check below */
        if (!vn_endpoint_check(e, why, sizeof why)) {
            vn_snprintf(err, errcap, "endpoint %s: %s", e->name, why);
            return 0;
        }
        if (had_file)
            e->token[0] = '\0';
    }
    for (i = 0; i < c->rules.n; i++) {
        char bad[VN_EP_NAME];

        if (!check_to(c, c->rules.rule[i].to, bad, sizeof bad)) {
            vn_snprintf(err, errcap, "rule %s: no endpoint called %s", c->rules.rule[i].name, bad);
            return 0;
        }
    }
    if (!check_to(c, c->defaults_to, why, sizeof why)) {
        vn_snprintf(err, errcap, "rules.defaults.to: no endpoint called %s", why);
        return 0;
    }
    if (c->defaults) {
        size_t first = c->rules.n;

        if (!vn_rules_add_defaults(&c->rules)) {
            vn_snprintf(err, errcap, "too many rules to add the defaults");
            return 0;
        }
        for (i = first; i < c->rules.n; i++) {
            if (c->defaults_to[0] != '\0')
                strcpy(c->rules.rule[i].to, c->defaults_to);
            if (c->defaults_throttle_s >= 0)
                c->rules.rule[i].throttle_s = c->defaults_throttle_s;
        }
    }
    if (c->nendpoints == 0) {
        vn_snprintf(err, errcap, "no [endpoint]: nothing to send to");
        return 0;
    }
    if (!c->opcom && !c->audit) {
        vn_snprintf(err, errcap, "logs.opcom and logs.audit are both no: nothing to read");
        return 0;
    }
    return 1;
}
