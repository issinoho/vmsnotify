/*
 * vmsnotify: rules. See rules.h.
 */

#include <ctype.h>
#include <string.h>

#include "rules.h"

/* From vmsotel's src/model/procfilter.c (vo_wildcard_match). Iterative,
   with one backtrack point for the last "*": linear in practice, and no
   recursion for a long pattern to exhaust. */
int vn_wildcard_match(const char *p, const char *t)
{
    const char *star = NULL, *mark = NULL;

    while (*t != '\0') {
        if (*p == '*') {
            star = p++;
            mark = t;
        } else if (*p == '%' ||
                   (*p != '\0' &&
                    toupper((unsigned char) *p) == toupper((unsigned char) *t))) {
            p++;
            t++;
        } else if (star != NULL) {
            p = star + 1;
            t = ++mark;
        } else {
            return 0;
        }
    }
    while (*p == '*')
        p++;
    return *p == '\0';
}

static const vn_log_attr *find_attr(const vn_log_rec *rec, const char *key)
{
    size_t i;

    for (i = 0; i < rec->nattrs; i++)
        if (strcmp(rec->attrs[i].key, key) == 0)
            return &rec->attrs[i];
    return NULL;
}

const char *vn_attr(const vn_log_rec *rec, const char *key)
{
    const vn_log_attr *a = find_attr(rec, key);

    return a != NULL && !a->is_int ? a->sval : NULL;
}

static const char *first_of(const vn_log_rec *rec, const char *a, const char *b)
{
    const char *v = vn_attr(rec, a);

    if (v == NULL && b != NULL)
        v = vn_attr(rec, b);
    return v != NULL ? v : "";
}

const char *vn_rec_user(const vn_log_rec *rec)
{
    if (rec->source == VN_LOG_OPCOM)
        return first_of(rec, "openvms.opcom.user", NULL);
    return first_of(rec, "openvms.audit.username", "openvms.audit.remote_username");
}

const char *vn_rec_terminal(const vn_log_rec *rec)
{
    return rec->source == VN_LOG_AUDIT ? first_of(rec, "openvms.audit.terminal", NULL) : "";
}

const char *vn_rec_remote(const vn_log_rec *rec)
{
    if (rec->source == VN_LOG_OPCOM)
        return "";
    return first_of(rec, "openvms.audit.remote_nodename",
                    "openvms.audit.remote_node_fullname");
}

/* 1 if word (len n) is one of the comma-separated items of list. Case-blind;
   spaces around items are ignored. */
static int in_list(const char *list, const char *word, size_t n)
{
    const char *p = list;

    while (*p != '\0') {
        const char *e;
        size_t len, k;

        while (*p == ' ' || *p == ',')
            p++;
        e = p;
        while (*e != '\0' && *e != ',')
            e++;
        len = (size_t) (e - p);
        while (len > 0 && p[len - 1] == ' ')
            len--;
        if (len == n && len > 0) {
            for (k = 0; k < n; k++)
                if (toupper((unsigned char) p[k]) != toupper((unsigned char) word[k]))
                    break;
            if (k == n)
                return 1;
        }
        p = e;
    }
    return 0;
}

/* 1 if value matches any of the comma-separated wildcard patterns. */
static int any_pattern(const char *list, const char *value)
{
    const char *p = list;

    while (*p != '\0') {
        char pat[VN_RULE_PAT];
        const char *e;
        size_t n;

        while (*p == ' ' || *p == ',')
            p++;
        e = p;
        while (*e != '\0' && *e != ',')
            e++;
        n = (size_t) (e - p);
        while (n > 0 && p[n - 1] == ' ')
            n--;
        if (n > 0 && n < sizeof pat) {
            memcpy(pat, p, n);
            pat[n] = '\0';
            if (vn_wildcard_match(pat, value))
                return 1;
        }
        p = e;
    }
    return 0;
}

static int pat_ok(const char *pat, const char *value)
{
    return pat[0] == '\0' || vn_wildcard_match(pat, value);
}

int vn_rule_matches(const vn_rule *r, const vn_log_rec *rec)
{
    if (r->source != 0 && r->source != rec->source)
        return 0;
    if (r->types[0] != '\0') {
        const char *t = rec->source == VN_LOG_AUDIT ? vn_attr(rec, "openvms.audit.type") : NULL;

        if (t == NULL || !in_list(r->types, t, strlen(t)))
            return 0;
    }
    if (r->min_severity != 0 && rec->severity < r->min_severity)
        return 0;
    if (r->request && (rec->source != VN_LOG_OPCOM ||
                       find_attr(rec, "openvms.opcom.request") == NULL))
        return 0;
    if (r->not_user[0] != '\0' && any_pattern(r->not_user, vn_rec_user(rec)))
        return 0;
    return pat_ok(r->user, vn_rec_user(rec)) &&
           pat_ok(r->terminal, vn_rec_terminal(rec)) &&
           pat_ok(r->remote, vn_rec_remote(rec)) &&
           pat_ok(r->text, rec->body);
}

const vn_rule *vn_rules_match(const vn_ruleset *rs, const vn_log_rec *rec)
{
    size_t i;

    for (i = 0; i < rs->n; i++)
        if (vn_rule_matches(&rs->rule[i], rec))
            return &rs->rule[i];
    return NULL;
}

int vn_rule_sends_to(const vn_rule *r, const char *endpoint)
{
    return r->to[0] == '\0' || in_list(r->to, endpoint, strlen(endpoint));
}

static void copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void vn_rule_init(vn_rule *r, const char *name)
{
    memset(r, 0, sizeof *r);
    copy(r->name, sizeof r->name, name);
    r->action = VN_ACT_NOTIFY;
    r->priority = VN_PRIO_NORMAL;
    r->throttle_s = VN_THROTTLE_DEFAULT;
}

int vn_rules_add(vn_ruleset *rs, const vn_rule *r)
{
    if (rs->n >= VN_RULES_MAX)
        return 0;
    rs->rule[rs->n++] = *r;
    return 1;
}

/*
 * The defaults: security events and problems. Audit types are NSADEF's
 * names, as vn_nsa_type_name gives them. Everything else -- logins,
 * logouts, object access, the operator log's hourly time stamps -- has
 * no rule, so it is not sent.
 */
static const struct {
    const char *name;
    int source;
    const char *types;
    int min_severity;
    int request;
    const char *user;
    const char *not_user;
    int priority;
} defaults[] = {
    { "breakin",       VN_LOG_AUDIT, "BREAKIN",         0, 0, "", "", VN_PRIO_URGENT },
    { "login-failure", VN_LOG_AUDIT, "LOGFAIL",         0, 0, "", "", VN_PRIO_HIGH },
    { "authorization", VN_LOG_AUDIT, "SYSUAF,RIGHTSDB", 0, 0, "", "", VN_PRIO_HIGH },
    { "auditing",      VN_LOG_AUDIT, "AUDIT,SERVER",    0, 0, "", "", VN_PRIO_HIGH },
    { "privileged",    VN_LOG_AUDIT, "PRVAUD,SYSTIME,SYSGEN,INSTALL", 0, 0, "", "", VN_PRIO_HIGH },
    { "opcom-error",   VN_LOG_OPCOM, "", VN_SEV_ERROR, 0, "", "", VN_PRIO_HIGH },
    { "opcom-warning", VN_LOG_OPCOM, "", VN_SEV_WARN,  0, "", "", VN_PRIO_NORMAL },
    { "opcom-request", VN_LOG_OPCOM, "", 0,            1, "", "", VN_PRIO_NORMAL },
    /* A person's message to the operators: a plain REQUEST is written as
       "Message from user IAIN on X86VMS", not as a numbered request
       (findings O2). "%*" is any user at all, so messages from no one
       (the log's time stamps) stay quiet, and SYSTEM's are routine. */
    { "opcom-message", VN_LOG_OPCOM, "", 0,            0, "%*", "SYSTEM", VN_PRIO_NORMAL }
};

int vn_rules_add_defaults(vn_ruleset *rs)
{
    size_t i;

    for (i = 0; i < sizeof defaults / sizeof defaults[0]; i++) {
        vn_rule r;

        vn_rule_init(&r, defaults[i].name);
        r.builtin = 1;
        r.source = defaults[i].source;
        copy(r.types, sizeof r.types, defaults[i].types);
        r.min_severity = defaults[i].min_severity;
        r.request = defaults[i].request;
        copy(r.user, sizeof r.user, defaults[i].user);
        copy(r.not_user, sizeof r.not_user, defaults[i].not_user);
        r.priority = defaults[i].priority;
        if (!vn_rules_add(rs, &r))
            return 0;
    }
    return 1;
}

const char *vn_prio_name(int prio)
{
    switch (prio) {
    case VN_PRIO_LOW:    return "low";
    case VN_PRIO_HIGH:   return "high";
    case VN_PRIO_URGENT: return "urgent";
    default:             return "normal";
    }
}

int vn_prio_parse(const char *s)
{
    static const char *names[] = { "low", "normal", "high", "urgent" };
    size_t i;

    for (i = 0; i < 4; i++)
        if (in_list(names[i], s, strlen(s)))
            return (int) i + 1;
    return 0;
}
