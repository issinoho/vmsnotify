/*
 * vmsnotify, from vmsotel's src/sources/logsource.h: the log source interface.
 *
 * Reads what has been written to the operator log and the audit journal
 * since the last commit, as log records. The VMS one (sources/vms/
 * vms_logs.c) reopens each file on every read and goes back to the last
 * record it committed by that record's RFA (vmsotel findings 35, 38); the fake
 * one (sources/fake/fake_logs.c) makes records up or takes them from a
 * file a test writes, so the agent runs end to end on Linux.
 *
 * Reading and committing are separate so that nothing is lost and
 * nothing sent twice: the agent reads a batch, queues what its rules
 * make of it, and commits only what it has dealt with.
 *
 * The read position across restarts (docs/design.md, D8) is vmsnotify's
 * own. The committed position of each log can be had as a string
 * (vn_logs_position), which the agent keeps in a file and gives back at
 * the next start. A source given one resumes there if it can and may:
 * the string must still name the same file and the same record, and what
 * was written after it must be within the catch-up limits. Otherwise it
 * starts at the end, as it does with no saved position, and says what it
 * skipped (vn_logs_notice), so that the gap is never silent.
 */

#ifndef VN_LOGSOURCE_H
#define VN_LOGSOURCE_H

#include <stddef.h>

#include "logparse.h"

/* A position string's size, with its NUL. One line of printable ASCII;
   what it says is the source's own business. */
#define VN_LOGS_POS_MAX 640

typedef struct {
    int opcom;                  /* read the operator log */
    int audit;                  /* read the audit journal */
    const char *opcom_file;
    const char *audit_file;

    /* Positions an earlier run saved, or NULL or "" for none: then that
       log is read from its end. */
    const char *opcom_pos;
    const char *audit_pos;
    /* Catch-up limits for a saved position. It is resumed only if the
       records written after it are no more than max_records and the
       oldest of them no older than max_age_s; 0 for either means no
       catching up at all. With nothing written after it, it is always
       resumed. */
    unsigned long max_age_s;
    unsigned long max_records;
} vn_logs_config;

/* Remembers c, which must outlive the source (the position strings too).
   Reads nothing yet: the first vn_logs_read goes to each saved position,
   or finds the end of the file and starts there. */
void vn_logs_open(const vn_logs_config *c);

/*
 * Fills recs with up to max records written since the last commit,
 * oldest first, the operator log's before the journal's. *more is 1 if
 * it stopped at max. Returns 1, or 0 if a file could not be read (the
 * other is still read). Either way msg may hold a line for the agent's
 * log, or be empty: parts joined by "; ", each either why a file could
 * not be read, beginning "cannot read " and the same at every read while
 * it lasts, or a note said once, such as where it started or what it
 * skipped.
 */
int vn_logs_read(vn_log_rec *recs, size_t max, size_t *n, int *more,
                 char *msg, size_t msgcap);

/* The first k records of the last read are dealt with: read past them. */
void vn_logs_commit(size_t k);

/*
 * The committed position of log source (VN_LOG_OPCOM or VN_LOG_AUDIT)
 * into buf, at least VN_LOGS_POS_MAX bytes. 1, or 0 with buf empty when
 * there is none: the log is off, or has not been read yet.
 */
int vn_logs_position(int source, char *buf, size_t cap);

/*
 * Records the source passed over without returning them: a saved
 * position it could not or might not resume, or a place lost while
 * running. 1 with a sentence for the people the agent notifies, once for
 * each such event; 0 when there is nothing to say. The same news is in
 * vn_logs_read's msg for the log.
 */
int vn_logs_notice(char *buf, size_t cap);

void vn_logs_close(void);

#endif
