/*
 * vmsnotify: notification endpoints, and what each sends.
 *
 * An endpoint is a server the site runs itself, reached directly:
 *   gotify   POST <base>/message, X-Gotify-Key: <application token>,
 *            JSON {title, message, priority 0-10}
 *   apprise  POST <base>/notify/<key> on an Apprise API server, JSON
 *            {title, body, type info|warning|failure, format text[, tag]};
 *            the destinations are in the server's stored configuration
 *            <key>, so no third-party address or secret is kept on VMS
 *   ntfy     POST <base>/<topic>, the body as text; headers Title,
 *            Priority 1-5, Tags
 *   webhook  POST <base>, a JSON event with every field of the message
 *            and its record (docs/webhook.md)
 * Credentials: gotify's token; for the others an optional bearer token
 * or user and password (basic). They go in headers only, never the path,
 * so the path can be logged.
 *
 * vn_endpoint_encode is pure; sending is the transport's.
 */

#ifndef VN_ENDPOINT_H
#define VN_ENDPOINT_H

#include <stddef.h>

#include "format.h"

enum { VN_EP_GOTIFY = 1, VN_EP_APPRISE, VN_EP_NTFY, VN_EP_WEBHOOK };

#define VN_EP_NAME  32
#define VN_EP_STR   256
#define VN_EP_HEADERS 1024

typedef struct {
    char name[VN_EP_NAME];
    int type;                   /* VN_EP_* */
    char host[VN_EP_STR];
    char port[8];
    char base[VN_EP_STR];       /* the URL's path, without a trailing / */
    int tls;
    char cafile[VN_EP_STR];     /* "" for the system's CAs */
    char token[VN_EP_STR];      /* gotify app token; else a bearer token */
    char user[64];              /* basic auth, with pass */
    char pass[VN_EP_STR];
    char key[64];               /* apprise: the stored configuration */
    char tag[64];               /* apprise: optional tag */
    char topic[64];             /* ntfy */
    int min_priority;           /* VN_PRIO_*: send nothing lower */
    unsigned timeout_s;
} vn_endpoint;

typedef struct {
    char path[2 * VN_EP_STR];
    char headers[VN_EP_HEADERS];   /* extra "Name: value\r\n" lines */
    const char *content_type;
    size_t body_len;
} vn_request;

/* Sets type, host, port, base and tls from "gotify" and
   "https://host[:port][/path]". 1, or 0 with a reason in err. */
int vn_endpoint_set_type(vn_endpoint *e, const char *type);
int vn_endpoint_set_url(vn_endpoint *e, const char *url, char *err, size_t errcap);

/* Checks what the type needs (gotify a token, apprise a key, ntfy a
   topic). 1, or 0 with a reason. */
int vn_endpoint_check(const vn_endpoint *e, char *err, size_t errcap);

/* Encodes m for e into body (capacity cap) and req. 1, or 0 if it does
   not fit. */
int vn_endpoint_encode(const vn_endpoint *e, const vn_msg *m,
                       char *body, size_t cap, vn_request *req);

const char *vn_endpoint_type_name(int type);

/* Each type's scale for a VN_PRIO_* priority. */
int vn_gotify_priority(int prio);       /* 2 5 8 10 */
int vn_ntfy_priority(int prio);         /* 2 3 4 5 */
const char *vn_apprise_type(int prio);  /* info info warning failure */

/* Standard Base64 of n bytes into out; out must hold 4*((n+2)/3)+1. */
void vn_base64(const unsigned char *in, size_t n, char *out);

#endif
