/*
 * vmsnotify, from vmsotel's src/transport/queue.h: a queue of messages waiting to be sent.
 *
 * The agent keeps one for each endpoint: encoded requests wait here
 * until that server takes them. It holds a fixed number of a fixed
 * maximum size, allocated once at startup; when it is full, one is
 * dropped to make room. A VMS production system must never fill its
 * memory or its disk because a notification server is down.
 *
 * Each entry carries a kind, the caller's own number. When the queue is
 * full, the oldest entry of the kind set with vn_queue_drop_first goes
 * first, and only if there is none the oldest of any (vmsotel drops
 * metrics before logs that way; vmsnotify sets no kind, so the oldest
 * message goes).
 */

#ifndef VN_QUEUE_H
#define VN_QUEUE_H

#include <stddef.h>

#define VN_QUEUE_MAX 64

typedef struct {
    char *mem;
    size_t slot_size;
    unsigned nslots;
    unsigned count;
    unsigned order[VN_QUEUE_MAX];   /* slots in use, oldest first */
    int used[VN_QUEUE_MAX];         /* by slot */
    size_t len[VN_QUEUE_MAX];       /* by slot */
    int kind[VN_QUEUE_MAX];         /* by slot */
    int drop_kind;                  /* dropped first; -1 for none */
    int dropped_kind;               /* what the last push dropped */
} vn_queue;

/* 1 on success, 0 if nslots is out of range or memory is short. */
int vn_queue_init(vn_queue *q, unsigned nslots, size_t slot_size);
void vn_queue_free(vn_queue *q);

/* The kind to drop first when the queue is full. */
void vn_queue_drop_first(vn_queue *q, int kind);

/* Copies a payload in. Returns 1 if one was dropped to make room (its
   kind in q->dropped_kind), 0 if not, -1 if the payload is larger than
   a slot. */
int vn_queue_push(vn_queue *q, const char *p, size_t n, int kind);

/* The oldest payload and its kind, or NULL when empty. */
const char *vn_queue_peek(const vn_queue *q, size_t *n, int *kind);
void vn_queue_pop(vn_queue *q);

#endif
