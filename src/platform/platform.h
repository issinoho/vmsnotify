/*
 * vmsnotify, from vmsotel's src/platform/platform.h: the platform interface.
 *
 * Everything the agent needs from the operating system beyond plain
 * C: a TCP stream, the time, a way to wait, and the node's name. Nothing here names a
 * sockaddr, a file descriptor or a timeval, so an implementation on
 * $QIO and $GETTIM is as possible as the POSIX one in
 * platform_posix.c. TLS sits above this interface (transport/tls.c),
 * not inside it, for the same reason.
 */

#ifndef VN_PLATFORM_H
#define VN_PLATFORM_H

#include <stddef.h>

#include "vn_types.h"

typedef struct vn_conn vn_conn;

/* Results of vn_net_recv() other than a byte count. */
#define VN_NET_CLOSED    0
#define VN_NET_ERROR   (-1)
#define VN_NET_TIMEOUT (-2)

/*
 * Opens a TCP connection to host:port, giving up after timeout_ms.
 * Returns NULL on failure with a reason in err.
 */
vn_conn *vn_net_connect(const char *host, const char *port, int timeout_ms,
                        char *err, size_t errcap);

/* Sends all n bytes. 1 on success, 0 on failure. */
int vn_net_send(vn_conn *c, const void *p, size_t n);

/* Receives up to n bytes, waiting at most timeout_ms. Returns the
   count, or VN_NET_CLOSED, VN_NET_ERROR or VN_NET_TIMEOUT. */
long vn_net_recv(vn_conn *c, void *p, size_t n, int timeout_ms);

void vn_net_close(vn_conn *c);

/* Wall-clock time, UTC, in Unix nanoseconds. */
vn_u64 vn_time_utc_ns(void);

/* A clock for intervals, in milliseconds from an arbitrary origin. It
   should not jump when the wall clock is set; on VMS, where it is
   time(), it does, so the agent treats a backward step as "now". It
   must never follow local time, which jumps at summer time. */
vn_u64 vn_time_mono_ms(void);

/* An interval clock as fine as the system offers, in nanoseconds, for
   timing work that takes milliseconds. On VMS it is $GETTIM, whose
   unit is 100 ns; on Linux, CLOCK_MONOTONIC. */
vn_u64 vn_time_precise_ns(void);

void vn_sleep_ms(vn_u32 ms);

/* This system's node name for the start of each title, upper case, into
   buf: "X86VMS". 1, or 0 with buf empty if the system has none. */
int vn_platform_node(char *buf, size_t cap);

#endif
