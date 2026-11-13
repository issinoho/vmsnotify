/*
 * vmsnotify, from vmsotel's src/transport/http.h: one OTLP/HTTP export -- an HTTP/1.1 POST, over TCP or TLS.
 *
 * Each export is its own connection with Connection: close. At one
 * request a minute that costs nothing worth saving, and it means no
 * idle connection for a firewall or a collector restart to break.
 */

#ifndef VN_HTTP_H
#define VN_HTTP_H

#include <stddef.h>

typedef struct {
    const char *host;
    const char *port;
    const char *path;
    int tls;
    const char *cafile;         /* NULL: the system's default CAs */
    int timeout_ms;             /* connect, and each read */
} vn_http_target;

typedef struct {
    int status;                 /* HTTP status, 0 if none was read */
    long retry_after_s;         /* -1 if the response gave none */
    int have_date;
    unsigned long date_unix;    /* the collector's Date header */
    long rejected;              /* partialSuccess.rejectedDataPoints or
                                   rejectedLogRecords, -1 if absent */
    char message[160];          /* errorMessage, or the transport error */
    char tls_info[96];          /* protocol and cipher, when TLS */
} vn_http_result;

/* What the agent should do with the payload. */
enum {
    VN_HTTP_SENT,               /* 2xx: delivered (check rejected) */
    VN_HTTP_RETRY,              /* no answer, 429, 5xx: keep it, try later */
    VN_HTTP_REJECTED            /* any other answer: retrying cannot help */
};

int vn_http_post(const vn_http_target *t, const char *body, size_t len,
                 vn_http_result *res);

/*
 * Parses a whole response (status line, headers, body) into res.
 * Returns the VN_HTTP_* outcome. Pure, so the tests can feed it
 * anything a collector might say.
 */
int vn_http_parse_response(const char *resp, size_t n, vn_http_result *res);

/* "Sat, 31 Oct 2026 12:34:56 GMT" to Unix seconds. 1 on success.
   1970 to 2105: an unsigned long of seconds is 32 bits on VMS. */
int vn_http_parse_date(const char *s, unsigned long *out);

#endif
