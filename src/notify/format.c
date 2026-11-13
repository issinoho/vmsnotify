/*
 * vmsnotify: turning records into messages. See format.h.
 */

#include <string.h>

#include "format.h"
#include "vn_types.h"

static void copy(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void scopy(char *dst, size_t cap, const char *src)
{
    copy(dst, cap, src, strlen(src));
}

/* Appends s to dst (capacity cap), cutting at the end. */
static void append(char *dst, size_t cap, const char *s)
{
    size_t n = strlen(dst);

    if (n + 1 < cap)
        copy(dst + n, cap - n, s, strlen(s));
}

/* Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm). */
static void civil_from_days(long z, int *y, int *m, int *d)
{
    long era, doe, yoe, doy, mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = (int) (doy - (153 * mp + 2) / 5 + 1);
    *m = (int) (mp < 10 ? mp + 3 : mp - 9);
    *y = (int) (yoe + era * 400 + (*m <= 2));
}

void vn_format_time(const vn_log_rec *rec, char *out, size_t cap)
{
    vn_u32 rem;
    vn_u64 secs;
    unsigned long s;
    int y, mo, d;

    if (vn_qzero(rec->time_ns)) {
        scopy(out, cap, "time unknown");
        return;
    }
    secs = vn_qdiv(rec->time_ns, 1000000000u, &rem);
    s = (unsigned long) vn_qlo(secs);   /* 32 bits of seconds: to 2106 */
    civil_from_days((long) (s / 86400ul), &y, &mo, &d);
    s %= 86400ul;
    vn_snprintf(out, cap, "%04d-%02d-%02d %02lu:%02lu:%02lu UTC", y, mo, d,
                s / 3600ul, s / 60ul % 60ul, s % 60ul);
}

/* The line of text starting at p, its length up to the newline. */
static size_t line_len(const char *p)
{
    const char *e = strchr(p, '\n');

    return e != NULL ? (size_t) (e - p) : strlen(p);
}

void vn_headline(const vn_log_rec *rec, char *out, size_t cap)
{
    const char *b = rec->body, *second;
    size_t n = line_len(b);

    out[0] = '\0';
    if (rec->source != VN_LOG_OPCOM) {
        copy(out, cap, b, n);
        return;
    }
    /* "Message from user IAIN on X86VMS" or "Request 3, from user IAIN
       on X86VMS", then the text: the text is the news. */
    second = b[n] == '\n' ? b + n + 1 : NULL;
    if (second != NULL && *second != '\0' &&
        (strncmp(b, "Message from user ", 18) == 0 ||
         strncmp(b, "Request ", 8) == 0)) {
        if (strncmp(b, "Request ", 8) == 0) {
            const char *c = strchr(b, ',');

            if (c != NULL && (size_t) (c - b) < n) {
                copy(out, cap, b, (size_t) (c - b));
                append(out, cap, ": ");
            }
        }
        n = line_len(second);
        if (strlen(out) + 1 < cap)
            copy(out + strlen(out), cap - strlen(out), second, n);
        return;
    }
    copy(out, cap, b, n);
}

static void title(vn_msg *m, const char *head)
{
    vn_snprintf(m->title, sizeof m->title, "%s: %s", m->node, head);
}

static void detail(vn_msg *m, const char *label, const char *value)
{
    if (value == NULL || value[0] == '\0')
        return;
    append(m->body, sizeof m->body, label);
    append(m->body, sizeof m->body, value);
    append(m->body, sizeof m->body, "\n");
}

static void begin(vn_msg *m, int kind, const char *node, int priority)
{
    memset(m, 0, sizeof *m);
    m->kind = kind;
    scopy(m->node, sizeof m->node, node);
    m->priority = priority;
}

void vn_format_event(vn_msg *m, const char *node, const vn_rule *r,
                     const vn_log_rec *rec)
{
    char head[VN_MSG_TITLE], when[40];

    begin(m, VN_MSG_EVENT, node, r->priority);
    scopy(m->rule, sizeof m->rule, r->name);
    scopy(m->to, sizeof m->to, r->to);
    m->rec = rec;
    vn_headline(rec, head, sizeof head);
    title(m, head);

    vn_format_time(rec, when, sizeof when);
    scopy(m->body, sizeof m->body, rec->body);
    append(m->body, sizeof m->body, "\n\n");
    if (rec->source == VN_LOG_AUDIT) {
        detail(m, "Event: ", vn_attr(rec, "openvms.audit.type"));
        detail(m, "User: ", vn_attr(rec, "openvms.audit.username"));
        detail(m, "Remote user: ", vn_attr(rec, "openvms.audit.remote_username"));
        detail(m, "Remote node: ", vn_rec_remote(rec));
        detail(m, "Terminal: ", vn_rec_terminal(rec));
        detail(m, "Image: ", vn_attr(rec, "openvms.audit.image"));
        detail(m, "Status: ", vn_attr(rec, "openvms.audit.status"));
    }
    detail(m, "Time: ", when);
    detail(m, "Node: ", node);
    detail(m, "Rule: ", r->name);
}

void vn_format_summary(vn_msg *m, const char *node, const vn_summary *s)
{
    char head[VN_MSG_TITLE];
    const char *label = s->label;
    size_t nl = strlen(node);

    begin(m, VN_MSG_SUMMARY, node, s->priority);
    scopy(m->rule, sizeof m->rule, s->rule);
    scopy(m->to, sizeof m->to, s->to);
    m->count = s->count;
    m->window_s = s->window_s;
    /* The label is the first event's title: drop its "NODE: ". */
    if (strncmp(label, node, nl) == 0 && label[nl] == ':' && label[nl + 1] == ' ')
        label += nl + 2;
    vn_snprintf(head, sizeof head, "%lu more: %s", s->count, label);
    title(m, head);
    vn_snprintf(m->body, sizeof m->body,
                "%lu more events matched rule %s%s%s within %ld s of the "
                "first, which was sent:\n%s\n",
                s->count, s->rule, s->key[0] ? " for " : "", s->key,
                s->window_s, label);
}

void vn_format_notice(vn_msg *m, const char *node, int priority,
                      const char *t, const char *body)
{
    begin(m, VN_MSG_NOTICE, node, priority);
    title(m, t);
    scopy(m->body, sizeof m->body, body);
}
