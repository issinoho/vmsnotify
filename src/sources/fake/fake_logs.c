/*
 * vmsnotify, from vmsotel's src/sources/fake/fake_logs.c: a log source for Linux, so the agent runs end to end
 * without VMS. See logsource.h. It works in one of two ways.
 *
 * From a file (VMSNOTIFY_FAKE_LOG_FILE=path), which a test writes and
 * appends to as OPCOM and the audit server would. One record a line:
 *
 *     TIME|opcom|TEXT                  \n in TEXT starts a new line
 *     TIME|audit|TYPE|USER|REMOTE      TYPE is NSADEF's: LOGFAIL, SYSUAF
 *     TIME|audit|TYPE|USER|REMOTE|AUDITUSER    the same, with a username
 *                                      too, as the Alpha writes (USER is
 *                                      the record's remote username)
 *
 * TIME is Unix seconds, or 0 for "when read". Lines starting with # do
 * not count; a last line without its newline is not there yet. The file
 * is opened afresh at every read, as the VMS reader opens its files.
 * Both kinds go through the real parsers: an operator message as the
 * header and text records OPCOM writes, an audit record as NSAMSGDEF
 * bytes.
 *
 * The file is both logs at once, and each has its own position: how many
 * of its lines have been consumed, and a hash of the last of them to
 * know it again -- what the VMS reader's RFA, length and first bytes
 * are. So everything the interface promises about a saved position is
 * real here and is what tools/agent_test.py tests: resuming without loss
 * or repeats, the catch-up limits, and a position that no longer fits
 * its file.
 *
 * Or made up (no VMSNOTIFY_FAKE_LOG_FILE), as in vmsotel: one record a
 * second after the first read, alternating between the two logs when
 * both are on, each numbered -- "fake operator message N", and a login
 * failure from user UN. VMSNOTIFY_FAKE_LOG_BURST=N has N waiting at the
 * first read. A saved position there only carries the numbering on.
 *
 * Either way, VMSNOTIFY_FAKE_LOG_FAIL=1 makes the audit journal
 * unreadable: only operator messages come, and every read says why.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logsource.h"
#include "platform.h"

#define FLINE_MAX  1024
#define AFTER_MAX  256

static const vn_logs_config *cfg;
static const char *path;            /* file mode, or NULL */
static char notice[400];

/* ---- building records ------------------------------------------------ */

static size_t put_pkt(unsigned char *b, size_t at, unsigned type,
                      const void *data, size_t n)
{
    b[at] = (unsigned char) ((n + 4) & 0xff);
    b[at + 1] = (unsigned char) ((n + 4) >> 8);
    b[at + 2] = (unsigned char) (type & 0xff);
    b[at + 3] = (unsigned char) (type >> 8);
    memcpy(b + at + 4, data, n);
    return at + 4 + n;
}

/* An audit record as x86 writes its login failures, of the given type. */
static void audit_rec(vn_log_rec *r, unsigned type, const char *user,
                      const char *node, const char *audit_user,
                      vn_u64 when_ns)
{
    unsigned char b[400], ts[8];
    /* when_ns as a VMS time: 100 ns units from 17-Nov-1858. */
    vn_u64 vms_time = vn_qadd(vn_qdiv(when_ns, 100, NULL),
                         vn_q(0x007C9567u, 0x4BEB4000u));
    size_t at = 20, ul = strlen(user), nl = strlen(node);
    unsigned count = 3;
    int i;

    if (ul > 64)
        ul = 64;
    if (nl > 120)
        nl = 120;
    for (i = 0; i < 4; i++) {
        ts[i] = (unsigned char) (vn_qlo(vms_time) >> (8 * i));
        ts[i + 4] = (unsigned char) (vn_qhi(vms_time) >> (8 * i));
    }
    at = put_pkt(b, at, 6, "SECURITY", 8);
    if (ul > 0) {
        at = put_pkt(b, at, 45, user, ul);
        count++;
    }
    if (nl > 0) {
        at = put_pkt(b, at, 44, node, nl);
        count++;
    }
    if (audit_user != NULL && audit_user[0] != '\0') {
        size_t al = strlen(audit_user);

        at = put_pkt(b, at, 56, audit_user, al > 64 ? 64 : al);
        count++;
    }
    at = put_pkt(b, at, 50, ts, 8);
    at = put_pkt(b, at, 7, "FAKE", 4);
    memset(b, 0, 20);
    b[0] = (unsigned char) type;
    b[2] = 5;
    b[4] = 0x1c;
    b[6] = (unsigned char) count;
    b[8] = (unsigned char) (at & 0xff);
    b[9] = (unsigned char) (at >> 8);
    b[11] = 3;
    vn_nsa_decode(b, at, 0, r);
}

/* An operator message, as the header and text records OPCOM writes,
   through the real parser. In text, the two characters \n end a line. */
static void opcom_rec(vn_log_rec *r, const char *text, vn_u64 when_ns)
{
    static const char mon[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";
    vn_opcom_parser p;
    time_t secs = (time_t) vn_qlo(vn_qdiv(when_ns, 1000000000u, NULL));
    struct tm *tm = gmtime(&secs);
    char head[80];
    const char *s = text;

    vn_opcom_init(&p, 0);
    vn_snprintf(head, sizeof head, "%%%%%%%%%%%%%%%%%%%%%%  OPCOM  "
                "%2d-%.3s-%04d %02d:%02d:%02d.00  %%%%%%%%%%%%%%%%%%%%%%",
                tm->tm_mday, mon + 3 * tm->tm_mon, tm->tm_year + 1900,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
    vn_opcom_feed(&p, head, strlen(head), r);
    for (;;) {
        const char *e = strstr(s, "\\n");
        size_t n = e != NULL ? (size_t) (e - s) : strlen(s);

        vn_opcom_feed(&p, s, n, r);
        if (e == NULL)
            break;
        s = e + 2;
    }
    if (!vn_opcom_feed(&p, "", 0, r))
        memset(r, 0, sizeof *r);
}

static unsigned nsa_code(const char *name)
{
    unsigned t;

    for (t = 1; t < 64; t++) {
        const char *n = vn_nsa_type_name(t);

        if (n != NULL && strcmp(n, name) == 0)
            return t;
    }
    return 5;                       /* LOGFAIL */
}

/* ---- file mode ------------------------------------------------------- */

/* Index 0 is the operator log, 1 the audit journal. */
typedef struct {
    int primed;
    unsigned long done;             /* lines of this kind consumed */
    unsigned long hash;             /* of the last of them; 0 with none */
} fpos;

typedef struct {
    unsigned long total;            /* lines of this kind */
    unsigned long last_hash;        /* of the last */
    unsigned long hash_at;          /* of line number `done` */
    unsigned long first_after;      /* time of line done + 1; 0 for now */
} fscan;

static fpos pos[2];
static struct {
    int kind;
    unsigned long seq, hash;
} after[AFTER_MAX];
static size_t last_n;
static char no_field[1];

static unsigned long hash_line(const char *s)
{
    unsigned long h = 2166136261ul;

    for (; *s != '\0'; s++)
        h = ((h ^ (unsigned char) *s) * 16777619ul) & 0xfffffffful;
    return h != 0 ? h : 1;
}

/* The next whole line that is a record: its kind (0, 1) and its fields
   cut apart in line, the line as it was in raw. 0 at the end. */
static int next_line(FILE *f, char *line, char *raw, int *kind,
                     unsigned long *when, char **f1, char **f2, char **f3)
{
    while (fgets(line, FLINE_MAX, f) != NULL) {
        size_t n = strlen(line);
        char *p, *k;

        if (n == 0 || line[n - 1] != '\n')
            return 0;               /* still being written */
        line[n - 1] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;
        strcpy(raw, line);
        if ((k = strchr(line, '|')) == NULL || (p = strchr(k + 1, '|')) == NULL)
            continue;
        *k++ = '\0';
        *p++ = '\0';
        *when = strtoul(line, NULL, 10);
        *f1 = p;
        *f2 = *f3 = no_field;
        if (strcmp(k, "opcom") == 0) {
            *kind = 0;
            return 1;
        }
        if (strcmp(k, "audit") != 0)
            continue;
        *kind = 1;
        if ((p = strchr(p, '|')) != NULL) {
            *p++ = '\0';
            *f2 = p;
            if ((p = strchr(p, '|')) != NULL) {
                *p++ = '\0';
                *f3 = p;
            }
        }
        return 1;
    }
    return 0;
}

/* Reads the whole file for what prime() and the place check need. */
static void scan(fscan sc[2])
{
    static char line[FLINE_MAX], raw[FLINE_MAX];
    FILE *f = fopen(path, "r");
    unsigned long when;
    char *f1, *f2, *f3;
    int k;

    memset(sc, 0, 2 * sizeof sc[0]);
    if (f == NULL)
        return;
    while (next_line(f, line, raw, &k, &when, &f1, &f2, &f3)) {
        sc[k].total++;
        sc[k].last_hash = hash_line(raw);
        if (sc[k].total == pos[k].done)
            sc[k].hash_at = sc[k].last_hash;
        if (sc[k].total == pos[k].done + 1)
            sc[k].first_after = when;
    }
    fclose(f);
}

static void add_msg(char *msg, size_t cap, const char *text)
{
    size_t have = strlen(msg);

    if (have > 0 && have + 2 < cap) {
        strcpy(msg + have, "; ");
        have += 2;
    }
    if (have < cap)
        vn_snprintf(msg + have, cap - have, "%s", text);
}

static const char *kind_name(int k)
{
    return k == 0 ? "operator log" : "audit journal";
}

/* Passes over everything in log k: its position becomes its end. */
static void to_end(int k, const fscan *sc)
{
    pos[k].done = sc->total;
    pos[k].hash = sc->total > 0 ? sc->last_hash : 0;
}

static void skip(int k, const fscan *sc, const char *why, char *msg,
                 size_t cap)
{
    char text[400];

    vn_snprintf(text, sizeof text, "%s (%s): %s; starting at its end",
                kind_name(k), path, why);
    add_msg(msg, cap, text);
    add_msg(notice, sizeof notice, text);
    to_end(k, sc);
}

/* The first read of log k: to its saved position if that holds and the
   limits allow, else to its end. */
static void prime(int k, char *msg, size_t cap)
{
    const char *saved = k == 0 ? cfg->opcom_pos : cfg->audit_pos;
    unsigned long done = 0, hash = 0, now, pending, age;
    fscan sc[2];
    char text[400], why[200];
    int at = 0;

    pos[k].primed = 1;
    if (saved == NULL || saved[0] == '\0') {
        scan(sc);
        to_end(k, &sc[k]);
        vn_snprintf(text, sizeof text, "starting at the end of the fake %s "
                    "(%lu records)", kind_name(k), sc[k].total);
        add_msg(msg, cap, text);
        return;
    }
    if (sscanf(saved, "fake1 %lu %lx %n", &done, &hash, &at) < 2 || at == 0 ||
        strcmp(saved + at, path) != 0) {
        scan(sc);
        skip(k, &sc[k], "the saved position is for another file", msg, cap);
        return;
    }
    pos[k].done = done;
    pos[k].hash = hash;
    scan(sc);
    if (sc[k].total < done || (done > 0 && sc[k].hash_at != hash)) {
        skip(k, &sc[k], "the record at the saved position is not the one "
             "saved, so what was written while vmsnotify was stopped is "
             "not known", msg, cap);
        return;
    }
    pending = sc[k].total - done;
    now = (unsigned long) vn_qlo(vn_qdiv(vn_time_utc_ns(), 1000000000u,
                                         NULL));
    age = sc[k].first_after != 0 && sc[k].first_after < now
          ? now - sc[k].first_after : 0;
    if (pending > cfg->max_records) {
        vn_snprintf(why, sizeof why, "%lu records were written while "
                    "vmsnotify was stopped, more than catchup.max_records "
                    "(%lu); they are skipped", pending, cfg->max_records);
        skip(k, &sc[k], why, msg, cap);
        return;
    }
    if (pending > 0 && (cfg->max_age_s == 0 || age > cfg->max_age_s)) {
        vn_snprintf(why, sizeof why, "the oldest of %lu records written "
                    "while vmsnotify was stopped is %lu s old, more than "
                    "catchup.max_age (%lu); they are skipped", pending,
                    age, cfg->max_age_s);
        skip(k, &sc[k], why, msg, cap);
        return;
    }
    vn_snprintf(text, sizeof text, "resuming the fake %s at its saved "
                "position: %lu records written while stopped",
                kind_name(k), pending);
    add_msg(msg, cap, text);
}

static int read_file(vn_log_rec *recs, size_t max, size_t *n, int *more,
                     char *msg, size_t cap, int fail)
{
    static char line[FLINE_MAX], raw[FLINE_MAX];
    int on[2], k;
    unsigned long seq[2] = { 0, 0 }, when;
    vn_u64 now_ns = vn_time_utc_ns();
    char *f1, *f2, *f3;
    fscan sc[2];
    FILE *f;

    on[0] = cfg->opcom;
    on[1] = cfg->audit && !fail;
    if (max > AFTER_MAX)
        max = AFTER_MAX;
    if ((f = fopen(path, "r")) == NULL) {
        char text[400];

        vn_snprintf(text, sizeof text, "cannot read %s: fake: no such file",
                    path);
        add_msg(msg, cap, text);
        return 0;
    }
    fclose(f);
    for (k = 0; k < 2; k++) {
        if (!on[k])
            continue;
        if (!pos[k].primed) {
            prime(k, msg, cap);
            continue;
        }
        /* Is the committed record still where it was? */
        scan(sc);
        if (sc[k].total < pos[k].done ||
            (pos[k].done > 0 && sc[k].hash_at != pos[k].hash))
            skip(k, &sc[k], "lost its place: the record at the committed "
                 "position has changed", msg, cap);
    }
    if ((f = fopen(path, "r")) == NULL)
        return 0;
    while (next_line(f, line, raw, &k, &when, &f1, &f2, &f3)) {
        vn_u64 t = when != 0 ? vn_qmul(vn_q32((vn_u32) when), 1000000000u)
                             : now_ns;

        seq[k]++;
        if (!on[k] || seq[k] <= pos[k].done)
            continue;
        if (*n == max) {
            *more = 1;
            break;
        }
        if (k == 0) {
            opcom_rec(&recs[*n], f1, t);
            recs[*n].file = cfg->opcom_file;
        } else {
            char *au = strchr(f3, '|');

            if (au != NULL)
                *au++ = '\0';
            audit_rec(&recs[*n], nsa_code(f1), f2, f3, au, t);
            recs[*n].file = cfg->audit_file;
        }
        after[*n].kind = k;
        after[*n].seq = seq[k];
        after[*n].hash = hash_line(raw);
        (*n)++;
    }
    fclose(f);
    return 1;
}

/* ---- made up --------------------------------------------------------- */

static vn_u64 t0_ms, t0_ns;
static unsigned long burst, base, committed;
static int started;

static void read_made_up(vn_log_rec *recs, size_t max, size_t *n, int *more,
                         char *msg, size_t cap, int fail)
{
    vn_u64 now = vn_time_mono_ms();
    unsigned long avail, i;
    int audit_on = cfg->audit && !fail;

    if (!cfg->opcom && !audit_on)
        return;
    if (!started) {
        const char *saved = cfg->opcom_pos != NULL && cfg->opcom_pos[0]
                            ? cfg->opcom_pos : cfg->audit_pos;

        started = 1;
        t0_ms = now;
        t0_ns = vn_time_utc_ns();
        if (saved != NULL)
            sscanf(saved, "gen1 %lu", &base);
        if (!fail)
            vn_snprintf(msg, cap, "fake logs: %lu waiting, then one a "
                        "second, numbered from %lu", burst, base + 1);
    }
    avail = burst + (unsigned long) vn_qlo(vn_qdiv(vn_qsub(now, t0_ms), 1000,
                                                    NULL));
    for (i = committed; i < avail && *n < max; i++) {
        unsigned long k = base + i + 1;
        int audit = audit_on && (!cfg->opcom || i % 2 == 1);
        vn_u64 when = vn_qadd(t0_ns, vn_qmul(vn_q32((vn_u32) i), 1000000000u));
        char user[24], node[48], text[96];

        if (audit) {
            vn_snprintf(user, sizeof user, "U%lu", k);
            vn_snprintf(node, sizeof node, "SSH_PASSWORD:192.0.2.%lu",
                        k % 250 + 1);
            audit_rec(&recs[*n], 5, user, node, NULL, when);
            recs[*n].file = cfg->audit_file;
        } else {
            vn_snprintf(text, sizeof text, "Message from user SYSTEM on "
                        "FAKE\\nfake operator message %lu", k);
            opcom_rec(&recs[*n], text, when);
            recs[*n].file = cfg->opcom_file;
        }
        (*n)++;
    }
    *more = i < avail;
}

/* ---- the interface --------------------------------------------------- */

void vn_logs_open(const vn_logs_config *c)
{
    const char *b = getenv("VMSNOTIFY_FAKE_LOG_BURST");

    cfg = c;
    path = getenv("VMSNOTIFY_FAKE_LOG_FILE");
    if (path != NULL && path[0] == '\0')
        path = NULL;
    burst = b ? strtoul(b, NULL, 10) : 0;
    base = committed = 0;
    started = 0;
    last_n = 0;
    notice[0] = '\0';
    memset(pos, 0, sizeof pos);
}

int vn_logs_read(vn_log_rec *recs, size_t max, size_t *n, int *more,
                 char *msg, size_t msgcap)
{
    int fail = getenv("VMSNOTIFY_FAKE_LOG_FAIL") != NULL && cfg->audit;
    int ok = 1;

    *n = 0;
    *more = 0;
    msg[0] = '\0';
    last_n = 0;
    if (fail)
        vn_snprintf(msg, msgcap, "cannot read %s: fake: no privilege",
                    cfg->audit_file);
    if (path != NULL)
        ok = read_file(recs, max, n, more, msg, msgcap, fail);
    else
        read_made_up(recs, max, n, more, msg, msgcap, fail);
    last_n = *n;
    return ok && !fail;
}

void vn_logs_commit(size_t k)
{
    size_t i;

    if (k > last_n)
        k = last_n;
    if (path == NULL) {
        committed += (unsigned long) k;
    } else {
        for (i = 0; i < k; i++) {
            pos[after[i].kind].done = after[i].seq;
            pos[after[i].kind].hash = after[i].hash;
        }
    }
    last_n = 0;
}

int vn_logs_position(int source, char *buf, size_t cap)
{
    int k = source == VN_LOG_AUDIT;

    buf[0] = '\0';
    if (!(k == 0 ? cfg->opcom : cfg->audit))
        return 0;
    if (path == NULL) {
        if (!started)
            return 0;
        vn_snprintf(buf, cap, "gen1 %lu", base + committed);
        return 1;
    }
    if (!pos[k].primed)
        return 0;
    vn_snprintf(buf, cap, "fake1 %lu %lx %s", pos[k].done, pos[k].hash, path);
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
