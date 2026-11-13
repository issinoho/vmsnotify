/*
 * vmsnotify, from vmsotel's src/sources/vms/vms_logs.c: the VMS log source -- the operator log and the audit journal,
 * read with RMS (phase 3). See logsource.h.
 *
 * What the probes found on both machines (vmsotel's docs/findings.md, 33-38), and
 * what this does about it:
 *   - Both files open for shared reading while OPCOM and the audit
 *     server write them, with READALL or SYSPRV, through RMS with every
 *     sharing option and no record locks -- as probe_logs opened them.
 *   - A stream left open never sees new records; a reopen does. So
 *     every read opens each file afresh and closes it again.
 *   - Going back to a record by its RFA works and is immediate, where
 *     reading I64's 4.5-million-record operator log takes 41 s. So the
 *     place kept between reads is the RFA of the last record consumed,
 *     with its length and first bytes to check it is still that record.
 *     The whole file is read once, at the first read, to find its end:
 *     the agent starts with what is new, not with years of history.
 *   - OPCOM writes no record after a message, so the last message in
 *     the log has nothing to end it until the next one comes. It is
 *     sent once it is unchanged over a whole interval.
 *   - Each file gets new versions (I64's journal did at 00:05 one day).
 *     Once the version being read has nothing new, the name without a
 *     version is looked up; a higher version is read from its start.
 *   - Times in both files are local: the system's differential is read
 *     on every read, so the hour after a summer-time change is right.
 *
 * The read position across restarts (docs/design.md, D8) is vmsnotify's
 * addition: pos_format, pos_parse, restore and their use in read_file,
 * below "the saved position". What it rests on was probed on x86
 * (probes/probe_position.c):
 *   - A record's RFA, kept with the file's specification with its
 *     version, finds the same record from another process later, in a
 *     file written to since: in test files and in the real OPERATOR.LOG
 *     and SECURITY.AUDIT$JOURNAL, opened as r_open opens them.
 *   - The NAM's resultant specification is a logical form
 *     (SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;251) and reopens; it is the FID
 *     that proves the file is the same one. All three of its words are
 *     kept and compared: the third (RVN, and NMX in its high byte) is
 *     not zero on the system's logs (256).
 *   - A saved version that has been deleted fails to open (RMS$_FNF):
 *     that is "start at the end and say what was skipped".
 *   - OPERATOR.LOG has records of no length, so the record saved may
 *     have length 0 and no first bytes; the position's format allows it.
 * NOT YET PROBED on IA64 or Alpha, and this code itself has run only
 * against stub/, whose RFA is a byte offset and whose FID is an inode:
 * phase 4 is its first run on VMS. If a machine says no, restore()
 * becomes "return 0" there and the agent starts at the end, saying so.
 *
 * Built without /POINTER_SIZE, like the rest of the VMS code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <descrip.h>
#include <rms.h>
#include <rmsdef.h>
#include <starlet.h>

#include "logsource.h"

#define REC_MAX   32768         /* the journal's longest: 32767 (finding 37) */
#define HEAD_MAX  64            /* bytes kept to know a record again */
#define AFTER_MAX 256           /* records one read can return */
#define RSS_MAX   255           /* NAM$C_MAXRSS */

/* in vms_sys.c */
int vn_vms_system_tdf(long *tdf, char *err, size_t errcap);

/* A record: where it is, and enough of it to know it again. */
typedef struct {
    unsigned short rfa[3];
    unsigned short len;
    unsigned char head[HEAD_MAX];
} vpos;

typedef struct {
    int kind;                   /* VN_LOG_OPCOM or VN_LOG_AUDIT */
    int on;
    const char *name;           /* as configured, no version */
    int primed;                 /* its end has been found */
    char spec[RSS_MAX + 1];     /* the version being read */
    unsigned short fid[3];      /* and its file identification */
    const char *saved;          /* an earlier run's position, tried once */
    int at_start;               /* committed: before its first record */
    vpos pos;                   /* committed: the last record consumed */
    /* OPCOM: the unfinished message at the end, as the last read saw it */
    int have_pend;
    vpos pend_hdr;
    size_t pend_lines;
} lfile;

typedef struct {
    struct FAB fab;
    struct RAB rab;
    struct NAM nam;
    char name[RSS_MAX + 1];
    char rsa[RSS_MAX + 1];
    unsigned short fid[3];
    int open;
} rfile;

static lfile files[2];
static const vn_logs_config *cfg;
static char notice[500];        /* for vn_logs_notice */
static unsigned char rec[REC_MAX];

/* Where each record of the last read leaves its file. */
static struct {
    int file;
    vpos pos;
} after[AFTER_MAX];
static size_t last_n;

static char *rms_msg(unsigned int st)
{
    static char text[256];
    unsigned short len = 0;
    struct dsc$descriptor_s d;

    d.dsc$w_length = (unsigned short) (sizeof text - 1);
    d.dsc$b_dtype = DSC$K_DTYPE_T;
    d.dsc$b_class = DSC$K_CLASS_S;
    d.dsc$a_pointer = text;
    if (!(sys$getmsg(st, &len, (void *) &d, 15, 0) & 1)) {
        sprintf(text, "%%X%08X", st);
        return text;
    }
    text[len] = '\0';
    return text;
}

/*
 * Opens for reading with every sharing option, so that a file another
 * process holds open for writing can be opened at all, and takes no
 * record locks. The NAM block gives the full name, version included.
 */
static unsigned int r_open(rfile *f, const char *name)
{
    unsigned int st;

    memset(f, 0, sizeof *f);
    strncpy(f->name, name, sizeof f->name - 1);
    f->fab = cc$rms_fab;
    f->nam = cc$rms_nam;
    f->fab.fab$l_fna = f->name;
    f->fab.fab$b_fns = (unsigned char) strlen(f->name);
    f->fab.fab$b_fac = FAB$M_GET;
    f->fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD;
    f->fab.fab$l_nam = &f->nam;
    f->nam.nam$l_rsa = f->rsa;
    f->nam.nam$b_rss = RSS_MAX;
    st = sys$open((void *) &f->fab);
    if (!(st & 1))
        return st;
    f->rsa[f->nam.nam$b_rsl] = '\0';
    memcpy(f->fid, f->nam.nam$w_fid, sizeof f->fid);
    f->rab = cc$rms_rab;
    f->rab.rab$l_fab = &f->fab;
    f->rab.rab$l_ubf = (char *) rec;
    f->rab.rab$w_usz = REC_MAX - 1;
    f->rab.rab$l_rop = RAB$M_NLK | RAB$M_RRL;
    f->rab.rab$b_rac = RAB$C_SEQ;
    st = sys$connect((void *) &f->rab);
    if (!(st & 1)) {
        sys$close((void *) &f->fab);
        return st;
    }
    f->open = 1;
    return st;
}

static void r_close(rfile *f)
{
    if (f->open)
        sys$close((void *) &f->fab);
    f->open = 0;
}

static unsigned int r_get(rfile *f, vpos *p)
{
    unsigned int st = sys$get((void *) &f->rab);
    unsigned short n;

    if (!(st & 1))
        return st;
    n = f->rab.rab$w_rsz;
    memcpy(p->rfa, f->rab.rab$w_rfa, sizeof p->rfa);
    p->len = n;
    memcpy(p->head, rec, n < HEAD_MAX ? n : HEAD_MAX);
    return st;
}

/* Back to the record at p, by its RFA: 1 if it is still that record,
   and the next r_get is the one after it. */
static int r_get_at(rfile *f, const vpos *p)
{
    unsigned int st;
    unsigned short n;

    memcpy(f->rab.rab$w_rfa, p->rfa, sizeof p->rfa);
    f->rab.rab$b_rac = RAB$C_RFA;
    st = sys$get((void *) &f->rab);
    f->rab.rab$b_rac = RAB$C_SEQ;
    if (!(st & 1))
        return 0;
    n = f->rab.rab$w_rsz;
    return n == p->len &&
           memcmp(rec, p->head, n < HEAD_MAX ? n : HEAD_MAX) == 0;
}

static int same_pos(const vpos *a, const vpos *b)
{
    return memcmp(a->rfa, b->rfa, sizeof a->rfa) == 0 && a->len == b->len;
}

static void add_msg(char *msg, size_t cap, const char *fmt, const char *a,
                    const char *b)
{
    size_t have = strlen(msg);

    if (have > 0 && have + 2 < cap) {
        strcpy(msg + have, "; ");
        have += 2;
    }
    if (have < cap)
        vn_snprintf(msg + have, cap - have, fmt, a, b);
}

void vn_logs_open(const vn_logs_config *c)
{
    cfg = c;
    notice[0] = '\0';
    memset(files, 0, sizeof files);
    files[0].saved = c->opcom_pos;
    files[1].saved = c->audit_pos;
    files[0].kind = VN_LOG_OPCOM;
    files[0].on = c->opcom;
    files[0].name = c->opcom_file;
    files[1].kind = VN_LOG_AUDIT;
    files[1].on = c->audit;
    files[1].name = c->audit_file;
    last_n = 0;
}

/*
 * The first read of a file: to its end, keeping only the last record's
 * place. What was there before the agent started is not sent.
 */
static int prime(lfile *lf, char *msg, size_t cap)
{
    rfile f;
    vpos p, last;
    unsigned long count = 0;
    time_t t0 = time(NULL);
    unsigned int st;
    char note[300];

    memset(&last, 0, sizeof last);
    st = r_open(&f, lf->name);
    if (!(st & 1)) {
        add_msg(msg, cap, "cannot read %s: %s", lf->name, rms_msg(st));
        return 0;
    }
    while ((st = r_get(&f, &p)) & 1) {
        last = p;
        count++;
    }
    strcpy(lf->spec, f.rsa);
    memcpy(lf->fid, f.fid, sizeof lf->fid);
    r_close(&f);
    lf->primed = 1;
    lf->have_pend = 0;
    lf->at_start = count == 0;
    if (count > 0)
        lf->pos = last;
    sprintf(note, "%lu records, %ld s", count, (long) (time(NULL) - t0));
    add_msg(msg, cap, "starting at the end of %s (%s)", lf->spec, note);
    return 1;
}

/* ---- the saved position (probed on x86 only: see the top) ------------- */

/*
 * A committed position as one line:
 *     rms1 SPEC FID,FID,FID S                       before its first record
 *     rms1 SPEC FID,FID,FID R RFA,RFA,RFA LEN HEAD  after that record
 * SPEC is the full specification with its version; the FID says it is
 * still that file and not another of the same name; RFA, LEN and HEAD
 * (the record's first bytes, in hex) are the vpos r_get_at checks. A
 * record of no length, which OPERATOR.LOG has, has "-" for its HEAD.
 */
static void pos_format(const lfile *lf, char *buf, size_t cap)
{
    size_t n, i, hl = lf->pos.len < HEAD_MAX ? lf->pos.len : HEAD_MAX;

    n = (size_t) vn_snprintf(buf, cap, "rms1 %s %u,%u,%u %s", lf->spec,
                             (unsigned) lf->fid[0], (unsigned) lf->fid[1],
                             (unsigned) lf->fid[2], lf->at_start ? "S" : "R");
    if (lf->at_start || n >= cap)
        return;
    n += (size_t) vn_snprintf(buf + n, cap - n, " %u,%u,%u %u ",
                              (unsigned) lf->pos.rfa[0],
                              (unsigned) lf->pos.rfa[1],
                              (unsigned) lf->pos.rfa[2],
                              (unsigned) lf->pos.len);
    for (i = 0; i < hl && n + 3 < cap; i++, n += 2)
        vn_snprintf(buf + n, cap - n, "%02x", (unsigned) lf->pos.head[i]);
    if (hl == 0 && n + 2 < cap)
        strcpy(buf + n, "-");
}

static int hexval(int c)
{
    return c >= '0' && c <= '9' ? c - '0'
         : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* 1 if s is a position pos_format wrote, taken apart. */
static int pos_parse(const char *s, char *spec, unsigned short fid[3],
                     int *at_start, vpos *p)
{
    unsigned f0, f1, f2, r0, r1, r2, len;
    char kind[2], hex[2 * HEAD_MAX + 2];
    size_t hl, i;
    int got;

    memset(p, 0, sizeof *p);
    hex[0] = '\0';
    /* 255 is RSS_MAX and 128 is 2 * HEAD_MAX: sscanf wants them spelled. */
    got = sscanf(s, "rms1 %255s %u,%u,%u %1s %u,%u,%u %u %128s", spec, &f0,
                 &f1, &f2, kind, &r0, &r1, &r2, &len, hex);
    if (got < 5 || f0 > 0xffff || f1 > 0xffff || f2 > 0xffff)
        return 0;
    fid[0] = (unsigned short) f0;
    fid[1] = (unsigned short) f1;
    fid[2] = (unsigned short) f2;
    if (kind[0] == 'S') {
        *at_start = 1;
        return got == 5;
    }
    if (kind[0] != 'R' || got != 10 || r0 > 0xffff || r1 > 0xffff ||
        r2 > 0xffff || len >= REC_MAX)
        return 0;
    *at_start = 0;
    p->rfa[0] = (unsigned short) r0;
    p->rfa[1] = (unsigned short) r1;
    p->rfa[2] = (unsigned short) r2;
    p->len = (unsigned short) len;
    hl = len < HEAD_MAX ? len : HEAD_MAX;
    if (hl == 0)
        return strcmp(hex, "-") == 0;
    if (strlen(hex) != 2 * hl)
        return 0;
    for (i = 0; i < hl; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return 0;
        p->head[i] = (unsigned char) (hi << 4 | lo);
    }
    return 1;
}

/*
 * Counts what f holds from where it stands to its end, as the agent
 * would get it: journal records, or operator messages. Stops counting
 * past limit. *oldest is the time of the first of them, Unix seconds, if
 * it is not known yet (0) and the record has one.
 */
static void count_rest(rfile *f, int kind, long tdf, unsigned long limit,
                       unsigned long *count, unsigned long *oldest)
{
    static vn_log_rec r;        /* too large for the stack on VMS */
    vn_opcom_parser parser;
    vpos p;

    vn_opcom_init(&parser, tdf);
    while (*count <= limit && (r_get(f, &p) & 1)) {
        int have;

        if (kind == VN_LOG_AUDIT)
            have = vn_nsa_decode(rec, p.len, tdf, &r) ? 1 : 2;
        else
            have = vn_opcom_feed(&parser, (const char *) rec, p.len, &r);
        if (!have)
            continue;
        (*count)++;
        if (*oldest == 0 && have == 1)
            *oldest = (unsigned long) vn_qlo(vn_qdiv(r.time_ns, 1000000000u,
                                                     NULL));
    }
    if (kind == VN_LOG_OPCOM && *count <= limit &&
        vn_opcom_pending(&parser, &r)) {
        (*count)++;
        if (*oldest == 0)
            *oldest = (unsigned long) vn_qlo(vn_qdiv(r.time_ns, 1000000000u,
                                                     NULL));
    }
}

static void skipped(const lfile *lf, const char *why, char *msg, size_t cap)
{
    add_msg(msg, cap, "%s: %s", lf->name, why);
    add_msg(notice, sizeof notice, "%s: %s", lf->name, why);
}

/*
 * The first read of a file an earlier run left a position for. Returns 1
 * with the file primed at that position when it still is that file and
 * that record and the catch-up limits allow what follows it; 0, having
 * said why, when the caller must start at the end instead.
 *
 * What follows it is everything after the record in that version, and,
 * if the name now leads to another version, all of that one too (the
 * reader goes from a finished version to the newest: read_file).
 */
static int restore(lfile *lf, const char *saved, long tdf, char *msg,
                   size_t cap)
{
    rfile f, g;
    vpos p;
    char spec[RSS_MAX + 1], why[300];
    unsigned short fid[3];
    unsigned long count = 0, oldest = 0, now = (unsigned long) time(NULL);
    unsigned long age;
    int at_start = 0;

    if (!pos_parse(saved, spec, fid, &at_start, &p)) {
        skipped(lf, "the saved read position cannot be understood; what "
                "was written while vmsnotify was stopped is skipped", msg,
                cap);
        return 0;
    }
    if (!(r_open(&f, spec) & 1)) {
        vn_snprintf(why, sizeof why, "%s, where vmsnotify stopped reading, "
                    "is gone; what was written while it was stopped is "
                    "skipped", spec);
        skipped(lf, why, msg, cap);
        return 0;
    }
    if (memcmp(f.fid, fid, sizeof fid) != 0 ||
        (!at_start && !r_get_at(&f, &p))) {
        r_close(&f);
        vn_snprintf(why, sizeof why, "%s is not the file it was, or the "
                    "record vmsnotify stopped at is no longer there; what "
                    "was written while it was stopped is skipped", spec);
        skipped(lf, why, msg, cap);
        return 0;
    }
    count_rest(&f, lf->kind, tdf, cfg->max_records, &count, &oldest);
    r_close(&f);
    if ((r_open(&g, lf->name) & 1)) {
        if (strcmp(g.rsa, spec) != 0)
            count_rest(&g, lf->kind, tdf, cfg->max_records, &count, &oldest);
        r_close(&g);
    }
    age = oldest != 0 && oldest < now ? now - oldest : 0;
    if (count > cfg->max_records) {
        vn_snprintf(why, sizeof why, "more than catchup.max_records (%lu) "
                    "records were written while vmsnotify was stopped; "
                    "they are skipped", cfg->max_records);
        skipped(lf, why, msg, cap);
        return 0;
    }
    if (count > 0 && (cfg->max_age_s == 0 || age > cfg->max_age_s)) {
        vn_snprintf(why, sizeof why, "the oldest of %lu records written "
                    "while vmsnotify was stopped is %lu s old, more than "
                    "catchup.max_age (%lu); they are skipped", count, age,
                    cfg->max_age_s);
        skipped(lf, why, msg, cap);
        return 0;
    }
    strcpy(lf->spec, spec);
    memcpy(lf->fid, fid, sizeof lf->fid);
    lf->at_start = at_start;
    lf->pos = p;
    lf->have_pend = 0;
    lf->primed = 1;
    vn_snprintf(why, sizeof why, "%lu records written while stopped", count);
    add_msg(msg, cap, "resuming in %s at the saved position (%s)", spec, why);
    return 1;
}

static void emit(vn_log_rec *recs, size_t *n, int file, const vpos *p,
                 const lfile *lf)
{
    recs[*n].file = lf->spec;
    after[*n].file = file;
    after[*n].pos = *p;
    (*n)++;
}

/*
 * Reads one file from its committed place: new records into recs from
 * *n on, up to max. Returns 0 if it could not be read.
 */
static int read_file(int file, vn_log_rec *recs, size_t max, size_t *n,
                     int *more, long tdf, char *msg, size_t cap)
{
    lfile *lf = &files[file];
    rfile f;
    vpos p, prev, hdr;
    vn_opcom_parser parser;
    unsigned int st;
    size_t first = *n;
    int have_prev = 0, eof = 0;

    if (!lf->primed && lf->saved != NULL && lf->saved[0] != '\0') {
        const char *saved = lf->saved;

        lf->saved = NULL;
        if (!restore(lf, saved, tdf, msg, cap))
            return prime(lf, msg, cap);
    }
    if (!lf->primed)
        return prime(lf, msg, cap);

    st = r_open(&f, lf->spec);
    if (!(st & 1)) {
        /* The version being read is gone (purged): carry on with the
           current one, from its start. */
        char now[RSS_MAX + 1];

        st = r_open(&f, lf->name);
        if (!(st & 1)) {
            add_msg(msg, cap, "cannot read %s: %s", lf->name, rms_msg(st));
            return 0;
        }
        strcpy(now, f.rsa);
        add_msg(msg, cap, "%s is gone; reading %s from its start",
                lf->spec, now);
        strcpy(lf->spec, now);
        memcpy(lf->fid, f.fid, sizeof lf->fid);
        lf->at_start = 1;
        lf->have_pend = 0;
    }
    if (!lf->at_start && !r_get_at(&f, &lf->pos)) {
        /* The record at the saved place is not the one saved. Starting
           over from the top could resend millions of records, so it
           starts again from the end and says so. */
        r_close(&f);
        lf->primed = 0;
        add_msg(msg, cap, "lost its place in %s; starting again from "
                "the end%s", lf->spec, "");
        add_msg(notice, sizeof notice, "lost its place in %s: what was "
                "written since the last read is skipped%s", lf->spec, "");
        return prime(lf, msg, cap) ? 1 : 0;
    }

    vn_opcom_init(&parser, tdf);
    memset(&hdr, 0, sizeof hdr);
    while (*n < max) {
        st = r_get(&f, &p);
        if (!(st & 1)) {
            eof = 1;
            break;
        }
        if (lf->kind == VN_LOG_AUDIT) {
            vn_log_rec *r = &recs[*n];

            if (!vn_nsa_decode(rec, p.len, tdf, r)) {
                memset(r, 0, sizeof *r);
                r->source = VN_LOG_AUDIT;
                r->severity = VN_SEV_WARN;
                r->severity_text = "WARN";
                sprintf(r->body, "Audit journal record of %u bytes that "
                        "does not decode as NSAMSGDEF", (unsigned) p.len);
            }
            emit(recs, n, file, &p, lf);
            continue;
        }
        /* OPCOM: a message ends at the record before this one. */
        if (vn_opcom_feed(&parser, (const char *) rec, p.len, &recs[*n]) &&
            have_prev)
            emit(recs, n, file, &prev, lf);
        if (vn_opcom_is_header((const char *) rec, p.len))
            hdr = p;
        prev = p;
        have_prev = 1;
    }
    if (!eof) {
        *more = 1;
        r_close(&f);
        return 1;
    }
    if (st != RMS$_EOF)
        add_msg(msg, cap, "reading %s: %s", lf->spec, rms_msg(st));

    /* The message at the end, once it has not grown for one read. */
    if (lf->kind == VN_LOG_OPCOM) {
        size_t lines = vn_opcom_pending_lines(&parser);

        if (lines == 0) {
            lf->have_pend = 0;
        } else if (lf->have_pend && same_pos(&lf->pend_hdr, &hdr) &&
                   lf->pend_lines == lines && *n < max) {
            vn_opcom_pending(&parser, &recs[*n]);
            emit(recs, n, file, &prev, lf);
            lf->have_pend = 0;
        } else {
            lf->have_pend = 1;
            lf->pend_hdr = hdr;
            lf->pend_lines = lines;
        }
    }
    r_close(&f);

    /* Nothing new and nothing waiting: has a new version begun? */
    if (*n == first && !lf->have_pend) {
        rfile g;

        if ((r_open(&g, lf->name) & 1)) {
            if (strcmp(g.rsa, lf->spec) != 0) {
                add_msg(msg, cap, "%s is finished; now reading %s",
                        lf->spec, g.rsa);
                strcpy(lf->spec, g.rsa);
                memcpy(lf->fid, g.fid, sizeof lf->fid);
                lf->at_start = 1;
            }
            r_close(&g);
        }
    }
    return 1;
}

int vn_logs_read(vn_log_rec *recs, size_t max, size_t *n, int *more,
                 char *msg, size_t msgcap)
{
    long tdf = 0;
    char err[200];
    int ok = 1, i;

    *n = 0;
    *more = 0;
    msg[0] = '\0';
    last_n = 0;
    if (max > AFTER_MAX)
        max = AFTER_MAX;
    if (!vn_vms_system_tdf(&tdf, err, sizeof err)) {
        /* vmsotel refuses to start without one. Here the events matter
           more than their times: they are read as UTC, and it is said
           once. */
        static int said;

        tdf = 0;
        if (!said)
            add_msg(msg, msgcap, "%s; times are taken as UTC%s", err, "");
        said = 1;
    }
    for (i = 0; i < 2; i++)
        if (files[i].on && !*more)
            ok &= read_file(i, recs, max, n, more, tdf, msg, msgcap);
    last_n = *n;
    return ok;
}

void vn_logs_commit(size_t k)
{
    size_t i;

    if (k > last_n)
        k = last_n;
    for (i = 0; i < k; i++) {
        lfile *lf = &files[after[i].file];

        lf->pos = after[i].pos;
        lf->at_start = 0;
    }
    last_n = 0;
}

int vn_logs_position(int source, char *buf, size_t cap)
{
    const lfile *lf = &files[source == VN_LOG_AUDIT];

    buf[0] = '\0';
    if (!lf->on || !lf->primed)
        return 0;
    pos_format(lf, buf, cap);
    return 1;
}

int vn_logs_notice(char *buf, size_t cap)
{
    if (notice[0] == '\0')
        return 0;
    vn_snprintf(buf, cap, "%s", notice);
    notice[0] = '\0';
    return 1;
}

void vn_logs_close(void)
{
}
