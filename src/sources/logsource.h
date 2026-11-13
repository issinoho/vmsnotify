/*
 * vmsnotify, from vmsotel's src/sources/logsource.h: the log source interface (phase 3).
 *
 * Reads what has been written to the operator log and the audit journal
 * since the last commit, as log records. The VMS one (sources/vms/
 * vms_logs.c) reopens each file on every read and goes back to the last
 * record it committed by that record's RFA (vmsotel findings 35, 38); the fake
 * one makes records up, so the agent runs end to end on Linux.
 *
 * Reading and committing are separate so that nothing is lost and
 * nothing sent twice: the agent reads a batch, queues as much of it as
 * it can, and commits only that. What it could not queue -- the queue
 * nearly full while the collector is down -- is read again next time.
 */

#ifndef VN_LOGSOURCE_H
#define VN_LOGSOURCE_H

#include <stddef.h>

#include "logparse.h"

typedef struct {
    int opcom;                  /* read the operator log */
    int audit;                  /* read the audit journal */
    const char *opcom_file;
    const char *audit_file;
} vn_logs_config;

/* Remembers c, which must outlive the source. Reads nothing yet: the
   first vn_logs_read finds the end of each file and starts there. */
void vn_logs_open(const vn_logs_config *c);

/*
 * Fills recs with up to max records written since the last commit,
 * oldest first, the operator log's before the journal's. *more is 1 if
 * it stopped at max. Returns 1, or 0 if a file could not be read (the
 * other is still read). Either way msg may hold a line for the agent's
 * log -- why a file could not be read, or a note such as where it
 * started -- or be empty.
 */
int vn_logs_read(vn_log_rec *recs, size_t max, size_t *n, int *more,
                 char *msg, size_t msgcap);

/* The first k records of the last read are queued: read past them. */
void vn_logs_commit(size_t k);

void vn_logs_close(void);

#endif
