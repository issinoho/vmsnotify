/*
 * vmsnotify: notification endpoints. See endpoint.h.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint.h"
#include "json.h"
#include "vn_types.h"

static void scopy(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int ieq(const char *a, const char *b)
{
    while (*a && *b && tolower((unsigned char) *a) == tolower((unsigned char) *b)) {
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static const char *type_names[] = { NULL, "gotify", "apprise", "ntfy", "webhook" };

const char *vn_endpoint_type_name(int type)
{
    return type >= VN_EP_GOTIFY && type <= VN_EP_WEBHOOK ? type_names[type] : "?";
}

int vn_endpoint_set_type(vn_endpoint *e, const char *type)
{
    int t;

    for (t = VN_EP_GOTIFY; t <= VN_EP_WEBHOOK; t++)
        if (ieq(type, type_names[t])) {
            e->type = t;
            return 1;
        }
    return 0;
}

int vn_endpoint_set_url(vn_endpoint *e, const char *url, char *err, size_t errcap)
{
    const char *p = url, *h, *he, *pe;
    size_t n;

    if (strncmp(p, "https://", 8) == 0) {
        e->tls = 1;
        p += 8;
        scopy(e->port, sizeof e->port, "443", 3);
    } else if (strncmp(p, "http://", 7) == 0) {
        e->tls = 0;
        p += 7;
        scopy(e->port, sizeof e->port, "80", 2);
    } else {
        vn_snprintf(err, errcap, "url must start http:// or https://");
        return 0;
    }
    h = p;
    he = p;
    while (*he && *he != ':' && *he != '/')
        he++;
    if (he == h || (size_t) (he - h) >= sizeof e->host) {
        vn_snprintf(err, errcap, "url has no host, or too long a one");
        return 0;
    }
    scopy(e->host, sizeof e->host, h, (size_t) (he - h));
    pe = he;
    if (*pe == ':') {
        const char *ps = ++pe;

        while (isdigit((unsigned char) *pe))
            pe++;
        n = (size_t) (pe - ps);
        if (n == 0 || n > 5 || (*pe && *pe != '/') ||
            strtol(ps, NULL, 10) < 1 || strtol(ps, NULL, 10) > 65535) {
            vn_snprintf(err, errcap, "url has a bad port");
            return 0;
        }
        scopy(e->port, sizeof e->port, ps, n);
    }
    n = strlen(pe);
    while (n > 0 && pe[n - 1] == '/')
        n--;
    if (n >= sizeof e->base) {
        vn_snprintf(err, errcap, "url path too long");
        return 0;
    }
    if (strchr(pe, '?') != NULL || strchr(pe, '#') != NULL) {
        vn_snprintf(err, errcap, "url must not have a query: put a token in token =");
        return 0;
    }
    scopy(e->base, sizeof e->base, pe, n);
    return 1;
}

int vn_endpoint_check(const vn_endpoint *e, char *err, size_t errcap)
{
    if (e->type == 0) {
        vn_snprintf(err, errcap, "no type (gotify, apprise, ntfy or webhook)");
        return 0;
    }
    if (e->host[0] == '\0') {
        vn_snprintf(err, errcap, "no url");
        return 0;
    }
    if (e->type == VN_EP_GOTIFY && e->token[0] == '\0') {
        vn_snprintf(err, errcap, "gotify needs an application token (token or token_file)");
        return 0;
    }
    if (e->type == VN_EP_APPRISE && e->key[0] == '\0') {
        vn_snprintf(err, errcap, "apprise needs key, its stored configuration's key");
        return 0;
    }
    if (e->type == VN_EP_NTFY && e->topic[0] == '\0') {
        vn_snprintf(err, errcap, "ntfy needs a topic");
        return 0;
    }
    if (e->token[0] != '\0' && e->user[0] != '\0' && e->type != VN_EP_GOTIFY) {
        vn_snprintf(err, errcap, "give token or user and password, not both");
        return 0;
    }
    return 1;
}

int vn_gotify_priority(int prio)
{
    static const int map[] = { 5, 2, 5, 8, 10 };

    return prio >= 1 && prio <= 4 ? map[prio] : 5;
}

int vn_ntfy_priority(int prio)
{
    static const int map[] = { 3, 2, 3, 4, 5 };

    return prio >= 1 && prio <= 4 ? map[prio] : 3;
}

const char *vn_apprise_type(int prio)
{
    return prio == VN_PRIO_URGENT ? "failure" : prio == VN_PRIO_HIGH ? "warning" : "info";
}

void vn_base64(const unsigned char *in, size_t n, char *out)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0;

    for (i = 0; i + 2 < n; i += 3) {
        unsigned long v = (unsigned long) in[i] << 16 | (unsigned long) in[i + 1] << 8 | in[i + 2];

        out[o++] = tab[v >> 18 & 63];
        out[o++] = tab[v >> 12 & 63];
        out[o++] = tab[v >> 6 & 63];
        out[o++] = tab[v & 63];
    }
    if (n - i == 1) {
        unsigned long v = (unsigned long) in[i] << 16;

        out[o++] = tab[v >> 18 & 63];
        out[o++] = tab[v >> 12 & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        unsigned long v = (unsigned long) in[i] << 16 | (unsigned long) in[i + 1] << 8;

        out[o++] = tab[v >> 18 & 63];
        out[o++] = tab[v >> 12 & 63];
        out[o++] = tab[v >> 6 & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* Appends "Name: value\r\n" to req->headers. The value is made one line
   of printable ASCII (a header is no place for 8-bit text or a CR/LF that
   would start another header). 0 if it does not fit. */
static int add_header(vn_request *req, const char *name, const char *value)
{
    size_t n = strlen(req->headers), nl = strlen(name), i;
    char *h = req->headers;

    if (n + nl + 2 + strlen(value) + 3 > sizeof req->headers)
        return 0;
    memcpy(h + n, name, nl);
    n += nl;
    h[n++] = ':';
    h[n++] = ' ';
    for (i = 0; value[i]; i++) {
        unsigned char c = (unsigned char) value[i];

        h[n++] = c >= 0x20 && c < 0x7f ? (char) c : (c >= 0xa0 ? '?' : ' ');
    }
    h[n++] = '\r';
    h[n++] = '\n';
    h[n] = '\0';
    return 1;
}

static int auth_header(const vn_endpoint *e, vn_request *req)
{
    char v[2 * VN_EP_STR + 16], raw[64 + VN_EP_STR + 2];
    size_t n;

    if (e->type == VN_EP_GOTIFY)
        return add_header(req, "X-Gotify-Key", e->token);
    if (e->token[0] != '\0') {
        vn_snprintf(v, sizeof v, "Bearer %s", e->token);
        return add_header(req, "Authorization", v);
    }
    if (e->user[0] != '\0') {
        n = (size_t) vn_snprintf(raw, sizeof raw, "%s:%s", e->user, e->pass);
        memcpy(v, "Basic ", 6);
        vn_base64((const unsigned char *) raw, n, v + 6);
        return add_header(req, "Authorization", v);
    }
    return 1;
}

static const char *kind_name(int kind)
{
    return kind == VN_MSG_SUMMARY ? "summary" : kind == VN_MSG_NOTICE ? "notice" : "event";
}

static void webhook_record(vn_json *j, const vn_log_rec *r)
{
    char when[40];
    size_t i;

    vn_json_key(j, "record");
    vn_json_begin(j);
    vn_json_kstr(j, "source", r->source == VN_LOG_AUDIT ? "audit" : "opcom");
    vn_format_time(r, when, sizeof when);
    vn_json_kstr(j, "time", when);
    {
        char ns[VN_QSTR_MAX];

        vn_json_key(j, "time_unix_ns");
        vn_json_str(j, vn_qstr(r->time_ns, ns));
    }
    vn_json_kstr(j, "severity", r->severity_text ? r->severity_text : "INFO");
    vn_json_kstr(j, "body", r->body);
    vn_json_key(j, "attributes");
    vn_json_begin(j);
    for (i = 0; i < r->nattrs; i++) {
        vn_json_key(j, r->attrs[i].key);
        if (r->attrs[i].is_int)
            vn_json_int(j, (long) r->attrs[i].ival);
        else
            vn_json_str(j, r->attrs[i].sval);
    }
    vn_json_end(j);
    vn_json_end(j);
}

int vn_endpoint_encode(const vn_endpoint *e, const vn_msg *m,
                       char *body, size_t cap, vn_request *req)
{
    vn_json j;
    int ok = 1;

    memset(req, 0, sizeof *req);
    req->content_type = "application/json";
    ok = auth_header(e, req);
    vn_json_init(&j, body, cap);

    switch (e->type) {
    case VN_EP_GOTIFY:
        vn_snprintf(req->path, sizeof req->path, "%s/message", e->base);
        vn_json_begin(&j);
        vn_json_kstr(&j, "title", m->title);
        vn_json_kstr(&j, "message", m->body);
        vn_json_kint(&j, "priority", vn_gotify_priority(m->priority));
        vn_json_end(&j);
        break;

    case VN_EP_APPRISE:
        vn_snprintf(req->path, sizeof req->path, "%s/notify/%s", e->base, e->key);
        vn_json_begin(&j);
        vn_json_kstr(&j, "title", m->title);
        vn_json_kstr(&j, "body", m->body);
        vn_json_kstr(&j, "type", vn_apprise_type(m->priority));
        vn_json_kstr(&j, "format", "text");
        if (e->tag[0] != '\0')
            vn_json_kstr(&j, "tag", e->tag);
        vn_json_end(&j);
        break;

    case VN_EP_NTFY: {
        char pr[4];
        const char *tags;

        vn_snprintf(req->path, sizeof req->path, "%s/%s", e->base, e->topic);
        req->content_type = "text/plain; charset=utf-8";
        vn_snprintf(pr, sizeof pr, "%d", vn_ntfy_priority(m->priority));
        tags = m->priority == VN_PRIO_URGENT ? "rotating_light,openvms"
             : m->priority == VN_PRIO_HIGH ? "warning,openvms" : "openvms";
        ok = ok && add_header(req, "Title", m->title) &&
             add_header(req, "Priority", pr) && add_header(req, "Tags", tags);
        req->body_len = vn_utf8(m->body, strlen(m->body), body, cap);
        return ok;
    }

    case VN_EP_WEBHOOK:
        vn_snprintf(req->path, sizeof req->path, "%s", e->base[0] ? e->base : "/");
        vn_json_begin(&j);
        vn_json_kstr(&j, "kind", kind_name(m->kind));
        vn_json_kstr(&j, "node", m->node);
        vn_json_kstr(&j, "title", m->title);
        vn_json_kstr(&j, "message", m->body);
        vn_json_kstr(&j, "priority", vn_prio_name(m->priority));
        if (m->rule[0] != '\0')
            vn_json_kstr(&j, "rule", m->rule);
        if (m->kind == VN_MSG_SUMMARY) {
            vn_json_kint(&j, "count", (long) m->count);
            vn_json_kint(&j, "window_s", m->window_s);
        }
        if (m->rec != NULL)
            webhook_record(&j, m->rec);
        vn_json_end(&j);
        break;

    default:
        return 0;
    }
    if (req->path[0] != '/') {
        size_t n = strlen(req->path);

        if (n + 1 < sizeof req->path) {
            memmove(req->path + 1, req->path, n + 1);
            req->path[0] = '/';
        }
    }
    req->body_len = j.len;
    return ok && !j.overflow;
}
