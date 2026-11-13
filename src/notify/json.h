/*
 * vmsnotify: a JSON writer into a fixed buffer.
 *
 * VMS text is 8-bit (DEC MCS, the same as ISO Latin-1 in its printable
 * range); JSON must be UTF-8. Strings are therefore written as Latin-1
 * to UTF-8, with control characters escaped. A write that would not fit
 * sets overflow and leaves the buffer short but terminated: the caller
 * checks overflow once at the end.
 */

#ifndef VN_JSON_H
#define VN_JSON_H

#include <stddef.h>

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
    int need_comma;
} vn_json;

void vn_json_init(vn_json *j, char *buf, size_t cap);
void vn_json_raw(vn_json *j, const char *s);
void vn_json_begin(vn_json *j);                 /* { */
void vn_json_end(vn_json *j);                   /* } */
void vn_json_key(vn_json *j, const char *key);  /* "key": (with a comma first if needed) */
void vn_json_str(vn_json *j, const char *s);    /* a string value */
void vn_json_strn(vn_json *j, const char *s, size_t n);
void vn_json_int(vn_json *j, long v);
void vn_json_kstr(vn_json *j, const char *key, const char *s);
void vn_json_kint(vn_json *j, const char *key, long v);

/* Latin-1 text to UTF-8, at most cap-1 bytes and terminated; a character
   that would not fit whole is left out. Control characters other than
   tab and newline become spaces. Returns the length. */
size_t vn_utf8(const char *s, size_t n, char *out, size_t cap);

#endif
