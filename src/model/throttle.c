/*
 * vmsnotify: throttling. See throttle.h.
 */

#include <string.h>

#include "throttle.h"

static void copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void vn_throttle_init(vn_throttle *t)
{
    memset(t, 0, sizeof *t);
}

static int is_hex(int c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

const char *vn_throttle_place(const char *remote)
{
    const char *p = remote;
    int nonhex = 0;

    while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
           *p == '_' || *p == '$') {
        if (!is_hex((unsigned char) *p))
            nonhex = 1;
        p++;
    }
    if (p > remote && *p == ':' && nonhex)
        return p + 1;
    return remote;
}

unsigned long vn_throttle_rec_s(const vn_log_rec *rec)
{
    /* A record that names no remote node is a local event, and two of
       them in a second are two events: no twins there. */
    if (vn_rec_remote(rec)[0] == '\0')
        return 0;
    return (unsigned long) vn_qlo(vn_qdiv(rec->time_ns, 1000000000u, NULL));
}

void vn_throttle_key(const vn_log_rec *rec, char *key, size_t cap)
{
    const char *who = rec->source == VN_LOG_AUDIT
                          ? vn_attr(rec, "openvms.audit.remote_username") : NULL;
    const char *place = vn_throttle_place(vn_rec_remote(rec));
    size_t n, i;

    if (who == NULL || who[0] == '\0')
        who = vn_rec_user(rec);
    copy(key, cap, who);
    for (i = 0; key[i] != '\0'; i++)
        if (key[i] >= 'a' && key[i] <= 'z')
            key[i] = (char) (key[i] - 'a' + 'A');
    if (place[0] != '\0') {
        n = strlen(key);
        if (n > 0 && n + 6 < cap) {
            memcpy(key + n, " from ", 6);
            key[n + 6] = '\0';
        }
        n = strlen(key);
        copy(key + n, cap - n, place);
    }
}

/* Moves an ended entry's summary to pending if it counted any, and frees
   it. 0 if pending is full (the entry is kept). */
static int retire(vn_throttle *t, vn_thr_entry *e)
{
    if (e->s.count > 0) {
        if (t->npending >= VN_THR_MAX)
            return 0;
        t->pending[t->npending++] = e->s;
    }
    e->used = 0;
    return 1;
}

static int admit(vn_throttle *t, const vn_rule *r, const char *key,
                 const char *label, unsigned long now_s)
{
    vn_thr_entry *free_e = NULL;
    size_t i;

    if (r->throttle_s <= 0)
        return VN_THR_SEND;
    for (i = 0; i < VN_THR_MAX; i++) {
        vn_thr_entry *e = &t->e[i];

        if (!e->used) {
            if (free_e == NULL)
                free_e = e;
            continue;
        }
        if (strcmp(e->s.rule, r->name) != 0 || strcmp(e->s.key, key) != 0)
            continue;
        if (now_s < e->window_end) {
            e->s.count++;
            return VN_THR_COUNTED;
        }
        /* Its window has ended: its summary is due, and this event opens
           a new window. */
        if (!retire(t, e))
            return VN_THR_SEND;
        free_e = e;
        break;
    }
    if (free_e == NULL) {
        /* Full: free a window that has ended, if there is one. */
        for (i = 0; i < VN_THR_MAX && free_e == NULL; i++)
            if (now_s >= t->e[i].window_end && retire(t, &t->e[i]))
                free_e = &t->e[i];
        if (free_e == NULL)
            return VN_THR_SEND;           /* send, untracked: never lose one */
    }
    memset(free_e, 0, sizeof *free_e);
    free_e->used = 1;
    free_e->window_end = now_s + (unsigned long) r->throttle_s;
    copy(free_e->s.rule, sizeof free_e->s.rule, r->name);
    copy(free_e->s.key, sizeof free_e->s.key, key);
    copy(free_e->s.label, sizeof free_e->s.label, label);
    copy(free_e->s.to, sizeof free_e->s.to, r->to);
    free_e->s.priority = r->priority;
    free_e->s.window_s = r->throttle_s;
    return VN_THR_SEND;
}


static unsigned long absdiff(unsigned long a, unsigned long b)
{
    return a > b ? a - b : b - a;
}

int vn_throttle_admit(vn_throttle *t, const vn_rule *r, const char *key,
                      const char *label, unsigned long now_s,
                      unsigned long rec_s)
{
    size_t i;
    int v;

    if (rec_s != 0)
        for (i = 0; i < VN_THR_RECENT; i++) {
            const vn_thr_recent *q = &t->recent[i];

            if (q->rec_s != 0 && absdiff(q->rec_s, rec_s) <= VN_THR_TWIN_S &&
                strcmp(q->rule, r->name) == 0 && strcmp(q->key, key) == 0)
                return VN_THR_DUP;
        }
    v = admit(t, r, key, label, now_s);
    if (rec_s != 0) {   /* sent or counted: its twin must not be */
        vn_thr_recent *q = &t->recent[t->next_recent];

        t->next_recent = (t->next_recent + 1) % VN_THR_RECENT;
        copy(q->rule, sizeof q->rule, r->name);
        copy(q->key, sizeof q->key, key);
        q->rec_s = rec_s;
    }
    return v;
}

size_t vn_throttle_due(vn_throttle *t, unsigned long now_s, int flush,
                       vn_summary *out, size_t max)
{
    size_t n = 0, i;

    for (i = 0; i < VN_THR_MAX; i++)
        if (t->e[i].used && (flush || now_s >= t->e[i].window_end))
            if (!retire(t, &t->e[i]))
                break;
    while (n < max && n < t->npending) {
        out[n] = t->pending[n];
        n++;
    }
    if (n > 0) {
        memmove(t->pending, t->pending + n, (t->npending - n) * sizeof t->pending[0]);
        t->npending -= n;
    }
    return n;
}
