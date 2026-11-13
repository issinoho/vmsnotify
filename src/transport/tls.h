/*
 * vmsnotify, from vmsotel's src/transport/tls.h: TLS over the platform interface.
 *
 * OpenSSL never sees a socket. It reads and writes two memory BIOs,
 * and this layer moves bytes between them and vn_net_send/vn_net_recv,
 * so TLS needs nothing from the platform but those two calls: a $QIO
 * implementation would carry it unchanged. Only POSIX has run.
 *
 * The certificate is always verified, against cafile if given and the
 * system's default locations otherwise, and the name or address
 * checked. There is no option to skip that (docs/design.md, TLS).
 */

#ifndef VN_TLS_H
#define VN_TLS_H

#include <stddef.h>

#include "platform.h"

typedef struct vn_tls vn_tls;

/* Handshakes over an open connection. NULL on failure, with a reason. */
vn_tls *vn_tls_open(vn_conn *conn, const char *host, const char *cafile,
                    int timeout_ms, char *err, size_t errcap);

/* As vn_net_send and vn_net_recv. */
int vn_tls_send(vn_tls *t, const void *p, size_t n);
long vn_tls_recv(vn_tls *t, void *p, size_t n);

/* "TLSv1.3 TLS_AES_128_GCM_SHA256", for the log. */
const char *vn_tls_describe(vn_tls *t, char *buf, size_t cap);

/* Sends close_notify and frees; the connection stays open. */
void vn_tls_close(vn_tls *t);

/* The OpenSSL version string, for the log. */
const char *vn_tls_library(void);

#endif
