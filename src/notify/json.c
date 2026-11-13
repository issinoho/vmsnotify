/*
 * vmsnotify: a JSON writer into a fixed buffer. See json.h.
 */

#include <string.h>

#include "json.h"
#include "vn_types.h"

void vn_json_init(vn_json *j, char *buf, size_t cap)
{
    j->buf = buf;
    j->cap = cap;
    j->len = 0;
    j->overflow = 0;
    j->need_comma = 0;
    if (cap > 0)
        buf[0] = '\0';
}

static void put(vn_json *j, const char *s, size_t n)
{
    if (j->overflow || j->len + n + 1 > j->cap) {
        j->overflow = 1;
        return;
    }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

void vn_json_raw(vn_json *j, const char *s)
{
    put(j, s, strlen(s));
}

void vn_json_begin(vn_json *j)
{
    if (j->need_comma)
        put(j, ",", 1);
    put(j, "{", 1);
    j->need_comma = 0;
}

void vn_json_end(vn_json *j)
{
    put(j, "}", 1);
    j->need_comma = 1;
}

void vn_json_key(vn_json *j, const char *key)
{
    if (j->need_comma)
        put(j, ",", 1);
    vn_json_strn(j, key, strlen(key));
    put(j, ":", 1);
    j->need_comma = 0;
}

void vn_json_strn(vn_json *j, const char *s, size_t n)
{
    size_t i;

    put(j, "\"", 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        char u[8];

        if (c == '"' || c == '\\') {
            u[0] = '\\';
            u[1] = (char) c;
            put(j, u, 2);
        } else if (c == '\n') {
            put(j, "\\n", 2);
        } else if (c == '\t') {
            put(j, "\\t", 2);
        } else if (c < 0x20 || c == 0x7f) {
            vn_snprintf(u, sizeof u, "\\u%04x", (unsigned) c);
            put(j, u, 6);
        } else if (c < 0x80) {
            u[0] = (char) c;
            put(j, u, 1);
        } else if (c < 0xa0) {
            put(j, " ", 1);     /* C1 controls */
        } else {
            u[0] = (char) (0xc0 | (c >> 6));
            u[1] = (char) (0x80 | (c & 0x3f));
            put(j, u, 2);
        }
    }
    put(j, "\"", 1);
    j->need_comma = 1;
}

void vn_json_str(vn_json *j, const char *s)
{
    vn_json_strn(j, s, strlen(s));
}

void vn_json_int(vn_json *j, long v)
{
    char n[24];

    vn_snprintf(n, sizeof n, "%ld", v);
    put(j, n, strlen(n));
    j->need_comma = 1;
}

void vn_json_kstr(vn_json *j, const char *key, const char *s)
{
    vn_json_key(j, key);
    vn_json_str(j, s);
}

void vn_json_kint(vn_json *j, const char *key, long v)
{
    vn_json_key(j, key);
    vn_json_int(j, v);
}

size_t vn_utf8(const char *s, size_t n, char *out, size_t cap)
{
    size_t i, o = 0;

    if (cap == 0)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];

        if (c == '\t' || c == '\n' || (c >= 0x20 && c < 0x7f)) {
            if (o + 2 > cap)
                break;
            out[o++] = (char) c;
        } else if (c < 0xa0) {
            if (o + 2 > cap)
                break;
            out[o++] = ' ';
        } else {
            if (o + 3 > cap)
                break;
            out[o++] = (char) (0xc0 | (c >> 6));
            out[o++] = (char) (0x80 | (c & 0x3f));
        }
    }
    out[o] = '\0';
    return o;
}
