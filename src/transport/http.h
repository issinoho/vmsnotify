/*
 * vmsnotify, from vmsotel's src/transport/http.h: one notification -- an HTTP/1.1 POST, over TCP or TLS.
 *
 * Each request is its own connection with Connection: close. At a few
 * messages an hour that costs nothing worth saving, and it means no
 * idle connection for a firewall or a server restart to break.
 *
 * Nothing here logs or returns a request header: headers carry the
 * tokens (docs/design.md, D7). The result's message is the transport's
 * own error or a short reason from the server's answer.
 */

#ifndef VN_HTTP_H
#define VN_HTTP_H

#include <stddef.h>

typedef struct {
    const char *host;
    const char *port;
    const char *path;
    const char *headers;        /* extra "Name: value\r\n" lines, or NULL;
                                   never logged: they hold the tokens */
    const char *content_type;   /* NULL: application/json */
    int tls;
    const char *cafile;         /* NULL: the system's default CAs */
    int timeout_ms;             /* connect, and each read */
} vn_http_target;

typedef struct {
    int status;                 /* HTTP status, 0 if none was read */
    long retry_after_s;         /* -1 if the response gave none */
    int have_date;
    unsigned long date_unix;    /* the server's Date header */
    char message[160];          /* the transport's error; or, for an answer
                                   that is not 2xx, a short reason from
                                   its body */
    char tls_info[96];          /* protocol and cipher, when TLS */
} vn_http_result;

/* What the agent should do with the payload. */
enum {
    VN_HTTP_SENT,               /* 2xx: delivered */
    VN_HTTP_RETRY,              /* no answer, 429, 5xx: keep it, try later */
    VN_HTTP_REJECTED            /* any other answer: retrying cannot help */
};

int vn_http_post(const vn_http_target *t, const char *body, size_t len,
                 vn_http_result *res);

/*
 * Parses a whole response (status line, headers, body) into res.
 * Returns the VN_HTTP_* outcome. Pure, so the tests can feed it
 * anything a server might say. The reason is the body's JSON
 * errorDescription (Gotify), error (Gotify, ntfy, Apprise) or message,
 * else the first 150 printable bytes of the body.
 */
int vn_http_parse_response(const char *resp, size_t n, vn_http_result *res);

/* "Sat, 31 Oct 2026 12:34:56 GMT" to Unix seconds. 1 on success.
   1970 to 2105: an unsigned long of seconds is 32 bits on VMS. */
int vn_http_parse_date(const char *s, unsigned long *out);

#endif
