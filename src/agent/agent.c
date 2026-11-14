/*
 * vmsnotify: the agent.
 *
 *     vmsnotify CONFIG [--log FILE] [--stop-file FILE] [--position FILE]
 *                      [--cycles N] [--drain SECONDS] [--dry-run]
 *     vmsnotify CONFIG --test
 *     vmsnotify --version
 *
 * Every interval it reads what the operator log and the audit journal
 * have gained. Each record goes to the first rule it matches: ignored,
 * or made a message unless the rule's throttle counts it into a window
 * already open. A message is encoded for every endpoint the rule sends
 * to whose min_priority it meets, and put on that endpoint's queue. Then
 * the records are committed and the read position saved, so a restart
 * goes on from there (docs/design.md, D8). Windows that have ended give
 * their summaries the same way.
 *
 * Each endpoint has its own queue and is sent to on its own: oldest
 * first; a failed send keeps the message and backs off, doubling from
 * one second to five minutes, or as long as the server's Retry-After
 * asks; an answer that says the request is wrong (401, 404) drops the
 * message with a line in the log, since sending it again cannot help. A
 * server that is down or hangs costs the others one timeout per attempt
 * and nothing more. A full queue drops its oldest message.
 *
 * Nothing that could hold a credential is ever logged: no request
 * header, and a server's answer only after anything equal to the
 * endpoint's token or password has been struck out of it. Paths can be
 * logged because a URL with a query is refused (D7).
 *
 * --test sends one notice to every endpoint, whatever its min_priority,
 * prints each result and exits non-zero if any failed. It reads no logs.
 *
 * --dry-run prints the messages that would be sent and to which
 * endpoints, and sends nothing; it reads no token file and leaves the
 * saved read position alone.
 *
 * --cycles N stops after N reads, once the queues are empty or --drain
 * seconds (default 15) have passed; the exit status says which. That is
 * for tests. Without it the agent runs until stopped.
 *
 * --position FILE is where the read position is kept; by default the
 * configuration file's name with the type .pos.
 *
 * The log goes to standard output, or with --log to a file, one line
 * per event, UTC.
 *
 * Stopping, as vmsotel does it. With --stop-file, the agent looks for
 * that file once a second; when it appears, the agent deletes it (the
 * acknowledgement the stop procedure waits for), sends the summaries of
 * the windows still open and a "stopped" notice, tries once to send what
 * is queued, logs what is still unsent and exits. SIGINT and SIGTERM do
 * the same. STOP/IDENTIFICATION cannot: it deletes the process without
 * running anything, so every failure line says how many are waiting.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "endpoint.h"
#include "format.h"
#include "http.h"
#include "logsource.h"
#include "platform.h"
#include "queue.h"
#include "rules.h"
#include "throttle.h"
#include "version.h"
#ifdef VN_WITH_TLS
#  include "tls.h"
#endif

#define MAX_BACKOFF_MS      300000ul    /* our own retries wait up to here */
#define MAX_RETRY_AFTER_MS  3600000ul   /* Retry-After is honoured up to here */
#define CONFIG_MAX      65536
#define LOG_BATCH       32              /* records read at a time */
#define LOG_ROUNDS      64              /* batches read per cycle */
#define BODY_MAX        16384           /* an encoded request body */
#define SHORT_BODY      600             /* what is kept of one that is larger */
/* A queued request: path, headers and content type, each with its NUL,
   then the body. */
#define SLOT_MAX        (2 * VN_EP_STR + VN_EP_HEADERS + 64 + BODY_MAX)
#define NSECRETS        3

static const char *log_path;
static const char *stop_path;
static volatile sig_atomic_t stop_signal;

/*
 * One line, to standard output or to --log. A log file is opened,
 * appended to and closed for every line: the VSI C RTL opens files for
 * exclusive access, so a log held open could not be read with TYPE while
 * the agent runs (vmsotel).
 *
 * No caller passes a request header, a token or a password.
 */
static void say(const char *fmt, ...)
{
    vn_u64 ns = vn_time_utc_ns();
    time_t secs = (time_t) vn_qlo(vn_qdiv(ns, 1000000000u, NULL));
    struct tm *tm = gmtime(&secs);
    char line[1024];
    size_t n = 0;
    va_list ap;
    FILE *f;

    if (tm != NULL)
        n = (size_t) vn_snprintf(line, sizeof line,
                                 "%04d-%02d-%02dT%02d:%02d:%02dZ ",
                                 tm->tm_year + 1900, tm->tm_mon + 1,
                                 tm->tm_mday, tm->tm_hour, tm->tm_min,
                                 tm->tm_sec);
    va_start(ap, fmt);
    vn_vsnprintf(line + n, sizeof line - n, fmt, ap);
    va_end(ap);

    if (log_path != NULL && (f = fopen(log_path, "a")) != NULL) {
        fprintf(f, "%s\n", line);
        fclose(f);
    } else {
        printf("%s\n", line);
        fflush(stdout);
    }
}

static void on_signal(int sig)
{
    (void) sig;
    stop_signal = 1;
}

/* A signal, or the stop file -- deleted once seen, so that it is the
   acknowledgement, and so that the next start does not stop at once. */
static int stop_requested(void)
{
    FILE *f;

    if (stop_signal)
        return 1;
    if (stop_path == NULL || (f = fopen(stop_path, "r")) == NULL)
        return 0;
    fclose(f);
    (void) remove(stop_path);
    return 1;
}

/* ---- the agent's state ----------------------------------------------- */

typedef struct {
    vn_endpoint *e;
    vn_queue q;
    unsigned long backoff_ms;
    vn_u64 next_send;           /* monotonic ms */
    unsigned fail_run;          /* failed attempts since the last success */
    vn_u64 fail_since;          /* monotonic ms of the first of them */
    unsigned long sent, failed, dropped;
    /* What must never reach the log: the token, the password, and the
       basic-authentication value made of it. */
    char secret[NSECRETS][2 * VN_EP_STR + 96];
} ep_state;

typedef struct {
    vn_config cfg;
    char node[32];
    ep_state ep[VN_ENDPOINTS_MAX];
    vn_throttle thr;
    vn_logs_config logs;
    int logs_on;
    char logs_err[400];         /* the read failure last logged */
    int dry_run;
    int stopping;               /* the last attempt: nothing is retried */

    const char *pos_path;
    char pos_given[2][VN_LOGS_POS_MAX];     /* as the last run left them */
    char pos_saved[2][VN_LOGS_POS_MAX];     /* as the file has them now */
    int pos_failed;

    unsigned long records, ignored, events, throttled, duplicates, summaries,
        notices;
} agent;

static vn_log_rec log_recs[LOG_BATCH];
static char body_buf[BODY_MAX];
static char slot_buf[SLOT_MAX];

/* Monotonic milliseconds: t plus ms, and b - a for a <= b, capped at
   what an unsigned long holds (32 bits on VMS: 49 days). */
static vn_u64 ms_after(vn_u64 t, unsigned long ms)
{
    return vn_qadd(t, vn_q32((vn_u32) ms));
}

static unsigned long ms_between(vn_u64 a, vn_u64 b)
{
    vn_u64 d;

    if (vn_qcmp(b, a) <= 0)
        return 0;
    d = vn_qsub(b, a);
    return vn_qhi(d) != 0 ? 0xFFFFFFFFul : (unsigned long) vn_qlo(d);
}

/* Seconds for the throttle, from the clock that does not follow the
   wall clock. */
static unsigned long mono_s(void)
{
    return (unsigned long) vn_qlo(vn_qdiv(vn_time_mono_ms(), 1000, NULL));
}

/* ---- files: the configuration, tokens, the read position -------------- */

static int read_config(const char *path, vn_config *c)
{
    static char text[CONFIG_MAX];
    char err[400];
    FILE *f = fopen(path, "r");
    size_t n;

    if (f == NULL) {
        say("cannot open configuration %s", path);
        return 0;
    }
    n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    if (n == sizeof text - 1) {
        say("configuration %s is larger than %d bytes", path, CONFIG_MAX - 1);
        return 0;
    }
    text[n] = '\0';
    if (!vn_config_parse(c, text, n, err, sizeof err)) {
        say("configuration %s: %s", path, err);
        return 0;
    }
    return 1;
}

/*
 * A token file holds the token and nothing else; space and line ends
 * around it are dropped. An empty one, or one with space or a control
 * character inside the token, is refused: the token goes into a header
 * as it is. The reason never quotes the file's content.
 */
static int read_token(const char *path, char *out, size_t cap,
                      const char **why)
{
    char buf[VN_EP_STR + 64];
    FILE *f = fopen(path, "r");
    size_t n, a = 0, i;

    if (f == NULL) {
        *why = "cannot be opened";
        return 0;
    }
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    while (n > 0 && (unsigned char) buf[n - 1] <= ' ')
        n--;
    while (a < n && (unsigned char) buf[a] <= ' ')
        a++;
    if (n == a) {
        *why = "is empty";
        return 0;
    }
    if (n - a >= cap) {
        *why = "holds more than a token";
        return 0;
    }
    for (i = a; i < n; i++)
        if ((unsigned char) buf[i] <= ' ' || (unsigned char) buf[i] >= 0x7f) {
            *why = "holds more than one printable word";
            return 0;
        }
    memcpy(out, buf + a, n - a);
    out[n - a] = '\0';
    return 1;
}

/* path with its file type replaced by .pos: next to the configuration,
   on Linux and on VMS ([CONF]VMSNOTIFY.CONF gives [CONF]VMSNOTIFY.pos;
   phase 4 will pass --position for [DATA]). */
static void default_pos_path(const char *config, char *out, size_t cap)
{
    size_t n = strlen(config), i, dot = n;

    for (i = n; i > 0; i--) {
        char c = config[i - 1];

        if (c == '/' || c == ']' || c == ':' || c == '>')
            break;
        if (c == '.' && dot == n)
            dot = i - 1;
        if (c == ';')
            dot = n = i - 1;    /* a VMS version number goes too */
    }
    if (dot + 5 > cap)
        dot = cap - 5;
    memcpy(out, config, dot);
    strcpy(out + dot, ".pos");
}

/* The positions the last run saved, by log: "opcom = ...", "audit = ...". */
static void load_positions(agent *a)
{
    char line[VN_LOGS_POS_MAX + 32];
    FILE *f = fopen(a->pos_path, "r");

    if (f == NULL)
        return;
    while (fgets(line, sizeof line, f) != NULL) {
        size_t n = strlen(line);
        int which;

        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (strncmp(line, "opcom = ", 8) == 0)
            which = 0;
        else if (strncmp(line, "audit = ", 8) == 0)
            which = 1;
        else
            continue;
        if (n - 8 < VN_LOGS_POS_MAX)
            strcpy(a->pos_given[which], line + 8);
    }
    fclose(f);
    memcpy(a->pos_saved, a->pos_given, sizeof a->pos_saved);
}

/*
 * Writes the committed positions if they have moved. On Linux the file
 * is replaced whole, by rename, so a crash leaves the old one or the new
 * one. On VMS a new version is written (rename there does not replace),
 * and once it is closed the version before it is deleted, so versions
 * do not pile up and a crash leaves at least one whole one (findings D4:
 * without this the hour's runs left a version per save).
 *
 * A log that has no position now -- it could not be read -- keeps the
 * one the last run left, to be tried again at the next start.
 */
static void save_positions(agent *a)
{
    char now[2][VN_LOGS_POS_MAX], tmp[VN_CONFIG_STR + 8];
    const char *target = a->pos_path;
    FILE *f;
    int ok;

    if (a->dry_run)
        return;
    if (!vn_logs_position(VN_LOG_OPCOM, now[0], sizeof now[0]))
        strcpy(now[0], a->pos_saved[0]);
    if (!vn_logs_position(VN_LOG_AUDIT, now[1], sizeof now[1]))
        strcpy(now[1], a->pos_saved[1]);
    if (strcmp(now[0], a->pos_saved[0]) == 0 &&
        strcmp(now[1], a->pos_saved[1]) == 0 && !a->pos_failed)
        return;
#ifndef __VMS
    vn_snprintf(tmp, sizeof tmp, "%s.new", a->pos_path);
    target = tmp;
#else
    tmp[0] = '\0';
#endif
    f = fopen(target, "w");
    ok = f != NULL;
    if (ok) {
        ok = fprintf(f, "# vmsnotify: where it has read to. Written by the "
                        "agent; delete it to start at the end of the logs.\n"
                        "opcom = %s\naudit = %s\n", now[0], now[1]) > 0;
        ok = fclose(f) == 0 && ok;
    }
#ifndef __VMS
    if (ok)
        ok = rename(tmp, a->pos_path) == 0;
#endif
    if (!ok) {
        if (!a->pos_failed)
            say("cannot write the read position to %s; a restart will not "
                "know where this run stopped", a->pos_path);
        a->pos_failed = 1;
        return;
    }
#ifdef __VMS
    if (strchr(a->pos_path, ';') == NULL) {
        vn_snprintf(tmp, sizeof tmp, "%s;-1", a->pos_path);
        (void)remove(tmp);          /* none on the first save: harmless */
    }
#endif
    if (a->pos_failed)
        say("read position written to %s again", a->pos_path);
    a->pos_failed = 0;
    memcpy(a->pos_saved, now, sizeof a->pos_saved);
}

/* ---- queueing --------------------------------------------------------- */

/* 1 if the message is for this endpoint: named by the rule (or the rule
   names none) and not below the endpoint's min_priority. */
static int wanted(const vn_msg *m, const vn_endpoint *e, int any_priority)
{
    static vn_rule to;

    strcpy(to.to, m->to);
    return vn_rule_sends_to(&to, e->name) &&
           (any_priority || m->priority >= e->min_priority);
}

/*
 * Encodes m for e into slot_buf as a queue slot. Returns its length, or
 * 0 if it cannot be encoded at all. A message too large for a request --
 * 8-bit text grows as UTF-8 and again as JSON -- is sent with the start
 * of its body and without its record, not dropped.
 */
static size_t encode_slot(const vn_endpoint *e, const vn_msg *m)
{
    static vn_msg cut;
    vn_request req;
    size_t pl, hl, cl;

    if (!vn_endpoint_encode(e, m, body_buf, sizeof body_buf, &req)) {
        cut = *m;
        cut.rec = NULL;
        if (strlen(cut.body) > SHORT_BODY)
            strcpy(cut.body + SHORT_BODY, "\n[cut short by vmsnotify]");
        if (!vn_endpoint_encode(e, &cut, body_buf, sizeof body_buf, &req))
            return 0;
        say("a message for %s was too large and is sent cut short: %s",
            e->name, m->title);
    }
    pl = strlen(req.path) + 1;
    hl = strlen(req.headers) + 1;
    cl = strlen(req.content_type) + 1;
    if (pl + hl + cl + req.body_len > sizeof slot_buf)
        return 0;
    memcpy(slot_buf, req.path, pl);
    memcpy(slot_buf + pl, req.headers, hl);
    memcpy(slot_buf + pl + hl, req.content_type, cl);
    memcpy(slot_buf + pl + hl + cl, body_buf, req.body_len);
    return pl + hl + cl + req.body_len;
}

/* A queue slot taken apart again into t and its body. */
static const char *slot_target(const char *p, size_t len, vn_http_target *t,
                               size_t *body_len)
{
    const char *body;

    t->path = p;
    t->headers = t->path + strlen(t->path) + 1;
    t->content_type = t->headers + strlen(t->headers) + 1;
    body = t->content_type + strlen(t->content_type) + 1;
    *body_len = len - (size_t) (body - p);
    return body;
}

static const char *kind_word(int kind)
{
    return kind == VN_MSG_SUMMARY ? "summary"
         : kind == VN_MSG_NOTICE ? "notice" : "event";
}

/* Queues m for every endpoint that wants it, and says so in one line.
   With --dry-run it is printed instead. */
static void deliver(agent *a, const vn_msg *m)
{
    char names[VN_ENDPOINTS_MAX * (VN_EP_NAME + 2) + 8];
    size_t i, nn = 0, count = 0;

    names[0] = '\0';
    for (i = 0; i < a->cfg.nendpoints; i++) {
        ep_state *s = &a->ep[i];
        size_t len;

        if (!wanted(m, s->e, 0))
            continue;
        if (!a->dry_run) {
            len = encode_slot(s->e, m);
            if (len == 0) {
                s->dropped++;
                say("a message cannot be encoded for %s; dropped: %s",
                    s->e->name, m->title);
                continue;
            }
            if (vn_queue_push(&s->q, slot_buf, len, 0) == 1) {
                s->dropped++;
                say("queue for %s full (%u); its oldest message is dropped",
                    s->e->name, s->q.nslots);
            }
        }
        nn += (size_t) vn_snprintf(names + nn, sizeof names - nn, "%s%s",
                                   count > 0 ? ", " : "", s->e->name);
        count++;
    }
    if (a->dry_run) {
        printf("--- %s, priority %s%s%s, to: %s\n%s\n%s\n",
               kind_word(m->kind), vn_prio_name(m->priority),
               m->rule[0] ? ", rule " : "", m->rule,
               count > 0 ? names : "no endpoint", m->title, m->body);
        fflush(stdout);
        return;
    }
    say("%s%s%s [%s] to %s: %s", kind_word(m->kind), m->rule[0] ? " " : "",
        m->rule, vn_prio_name(m->priority),
        count > 0 ? names : "no endpoint", m->title);
}

static void notice(agent *a, int priority, const char *title,
                   const char *body)
{
    static vn_msg m;

    if (!a->cfg.notices)
        return;
    vn_format_notice(&m, a->node, priority, title, body);
    a->notices++;
    deliver(a, &m);
}

/* ---- reading ---------------------------------------------------------- */

static void handle_record(agent *a, const vn_log_rec *rec)
{
    static vn_msg m;
    const vn_rule *r = vn_rules_match(&a->cfg.rules, rec);
    char key[VN_THR_KEY];

    a->records++;
    if (r == NULL || r->action != VN_ACT_NOTIFY) {
        a->ignored++;
        return;
    }
    vn_format_event(&m, a->node, r, rec);
    vn_throttle_key(rec, key, sizeof key);
    switch (vn_throttle_admit(&a->thr, r, key, m.title, mono_s(),
                              vn_throttle_rec_s(rec))) {
    case VN_THR_COUNTED:
        a->throttled++;
        return;
    case VN_THR_DUP:
        /* The twin of an event just sent (Alpha writes two records for
           one SSH login failure): only counted here, in the final line. */
        a->duplicates++;
        return;
    default:
        break;
    }
    a->events++;
    deliver(a, &m);
}

/* Summaries of the windows that have ended; all of them with flush. */
static void summaries(agent *a, int flush)
{
    static vn_msg m;
    vn_summary s[4];
    size_t n, i;

    while ((n = vn_throttle_due(&a->thr, mono_s(), flush, s, 4)) > 0)
        for (i = 0; i < n; i++) {
            vn_format_summary(&m, a->node, &s[i]);
            a->summaries++;
            deliver(a, &m);
        }
}

/*
 * A source's msg is parts joined by "; ". Those that say a file cannot
 * be read ("cannot read ...", logsource.h) go to err, which is compared
 * from one read to the next; the rest, said once each by the source, to
 * notes.
 */
static void split_msg(const char *msg, char *err, size_t errcap, char *notes,
                      size_t notescap)
{
    const char *p = msg;

    err[0] = notes[0] = '\0';
    while (*p != '\0') {
        const char *e = strstr(p, "; ");
        size_t n = e != NULL ? (size_t) (e - p) : strlen(p);
        int is_err = strncmp(p, "cannot read ", 12) == 0;
        char *out = is_err ? err : notes;
        size_t cap = is_err ? errcap : notescap, have = strlen(out);

        if (have + n + 3 < cap) {
            if (have > 0) {
                strcpy(out + have, "; ");
                have += 2;
            }
            memcpy(out + have, p, n);
            out[have + n] = '\0';
        }
        p = e != NULL ? e + 2 : p + n;
    }
}

/*
 * One cycle: what the logs have gained, through the rules and onto the
 * queues; then those records are committed and the position saved. A
 * record is dealt with once it is queued or decided against -- a full
 * queue drops its oldest message rather than refuse a new one -- so the
 * whole batch is committed. A failure to read is logged, and noticed,
 * when it starts, changes or ends, not every interval.
 */
static void cycle(agent *a)
{
    char msg[600], err[600], notes[600], text[700];
    size_t n, i;
    int more, ok, round;

    for (round = 0; a->logs_on && round < LOG_ROUNDS; round++) {
        n = 0;
        more = 0;
        ok = vn_logs_read(log_recs, LOG_BATCH, &n, &more, msg, sizeof msg);
        split_msg(msg, err, sizeof err, notes, sizeof notes);
        if (notes[0] != '\0')
            say("logs: %s", notes);
        if (!ok && err[0] == '\0')
            vn_snprintf(err, sizeof err, "a log cannot be read");
        if (!ok) {
            if (strcmp(err, a->logs_err) != 0) {
                say("logs: %s", err);
                if (a->logs_err[0] == '\0') {
                    vn_snprintf(text, sizeof text, "%s\n\nNothing from that "
                                "log is sent until it can be read; both "
                                "need READALL.", err);
                    notice(a, VN_PRIO_HIGH, "vmsnotify cannot read a log",
                           text);
                }
            }
            vn_snprintf(a->logs_err, sizeof a->logs_err, "%s", err);
        } else if (a->logs_err[0] != '\0') {
            say("logs: readable again");
            notice(a, VN_PRIO_NORMAL, "vmsnotify can read its logs again",
                   "The log that could not be read can be read again. "
                   "What was written to it meanwhile is not sent.");
            a->logs_err[0] = '\0';
        }
        while (vn_logs_notice(msg, sizeof msg)) {
            vn_snprintf(text, sizeof text, "%s\n\nEvents in the skipped "
                        "records were not sent. catchup.max_age and "
                        "catchup.max_records set how far back a start "
                        "goes.", msg);
            notice(a, VN_PRIO_HIGH, "vmsnotify skipped log records", text);
        }
        for (i = 0; i < n; i++)
            handle_record(a, &log_recs[i]);
        vn_logs_commit(n);
        save_positions(a);
        if (n == 0 || !more)
            break;
    }
    summaries(a, 0);
}

/* ---- sending ---------------------------------------------------------- */

/* Strikes the endpoint's secrets out of text a server sent back, in
   case it quoted the request. */
static void scrub(char *text, const ep_state *s)
{
    int i;

    for (i = 0; i < NSECRETS; i++) {
        size_t n = strlen(s->secret[i]);
        char *p = text;

        if (n < 4)
            continue;
        while ((p = strstr(p, s->secret[i])) != NULL) {
            memset(p, '*', n);
            p += n;
        }
    }
}

static void fill_target(const vn_endpoint *e, vn_http_target *t)
{
    memset(t, 0, sizeof *t);
    t->host = e->host;
    t->port = e->port;
    t->tls = e->tls;
    t->cafile = e->cafile[0] ? e->cafile : NULL;
    t->timeout_ms = (int) e->timeout_s * 1000;
}

/* Sends the endpoint's oldest message. Returns 1 if its queue moved on. */
static int send_one(agent *a, ep_state *s)
{
    vn_http_target t;
    vn_http_result r;
    size_t len, body_len;
    int kind = 0, outcome;
    const char *p = vn_queue_peek(&s->q, &len, &kind), *body;

    if (p == NULL)
        return 0;
    fill_target(s->e, &t);
    body = slot_target(p, len, &t, &body_len);
    outcome = vn_http_post(&t, body, body_len, &r);
    scrub(r.message, s);

    if (outcome == VN_HTTP_SENT) {
        vn_queue_pop(&s->q);
        s->sent++;
        s->backoff_ms = 0;
        /* Say when an outage ends, or the log shows only that it began. */
        if (s->fail_run > 0)
            say("%s: sent again after %u failed attempt%s over %lu s",
                s->e->name, s->fail_run, s->fail_run == 1 ? "" : "s",
                ms_between(s->fail_since, vn_time_mono_ms()) / 1000);
        s->fail_run = 0;
        return 1;
    }
    if (outcome == VN_HTTP_REJECTED) {
        /* t.path is still the slot's: log before the pop frees it. */
        say("%s: REJECTED, HTTP %d on %s: %s -- message dropped; %s",
            s->e->name, r.status, t.path,
            r.message[0] ? r.message : "(no reason given)",
            r.status == 401 || r.status == 403
            ? "check the endpoint's token or user and password"
            : r.status == 404
            ? "check the endpoint's url, key or topic"
            : r.status == 0 ? "check the endpoint's url"
            : "sending it again cannot help");
        vn_queue_pop(&s->q);
        s->dropped++;
        return 1;
    }

    s->failed++;
    if (s->fail_run++ == 0)
        s->fail_since = vn_time_mono_ms();
    if (a->stopping) {
        if (r.status != 0)
            say("%s: failed, HTTP %d%s%s; %u waiting", s->e->name, r.status,
                r.message[0] ? ": " : "", r.message, s->q.count);
        else
            say("%s: failed: %s; %u waiting", s->e->name, r.message,
                s->q.count);
        return 0;
    }
    s->backoff_ms = s->backoff_ms == 0 ? 1000 : s->backoff_ms * 2;
    if (s->backoff_ms > MAX_BACKOFF_MS)
        s->backoff_ms = MAX_BACKOFF_MS;
    if (r.retry_after_s >= 0) {
        /* Capped before multiplying: a long of ms is 32 bits on VMS. */
        unsigned long ra = r.retry_after_s >= (long) (MAX_RETRY_AFTER_MS / 1000)
                           ? MAX_RETRY_AFTER_MS
                           : (unsigned long) r.retry_after_s * 1000;

        if (ra > s->backoff_ms)
            s->backoff_ms = ra;
    }
    if (r.status != 0)
        say("%s: failed, HTTP %d%s%s; retrying in %lu ms; %u waiting",
            s->e->name, r.status, r.message[0] ? ": " : "", r.message,
            s->backoff_ms, s->q.count);
    else
        say("%s: failed: %s; retrying in %lu ms; %u waiting", s->e->name,
            r.message, s->backoff_ms, s->q.count);
    return 0;
}

/* Every endpoint whose time has come sends until its queue is empty or
   a send fails. */
static void send_due(agent *a)
{
    size_t i;

    for (i = 0; i < a->cfg.nendpoints; i++) {
        ep_state *s = &a->ep[i];

        while (s->q.count > 0 &&
               (a->stopping || vn_qcmp(vn_time_mono_ms(), s->next_send) >= 0))
            if (!send_one(a, s)) {
                s->next_send = ms_after(vn_time_mono_ms(), s->backoff_ms);
                break;
            }
    }
}

static unsigned waiting(const agent *a)
{
    unsigned n = 0;
    size_t i;

    for (i = 0; i < a->cfg.nendpoints; i++)
        n += a->ep[i].q.count;
    return n;
}

/* The last of a run: what the open windows counted, and a goodbye. */
static void wind_up(agent *a)
{
    summaries(a, 1);
    notice(a, VN_PRIO_LOW, "vmsnotify stopped",
           "vmsnotify " VN_VERSION " has stopped. Nothing is sent from "
           "this system's logs until it is started again.");
}

/* An account of the run and of whatever could not go. Nothing is lost
   silently. Returns the number of messages left unsent. */
static unsigned account(agent *a, const char *word, unsigned long cycles)
{
    unsigned long sent = 0, failed = 0, dropped = 0;
    unsigned lost = waiting(a);
    size_t i;

    for (i = 0; i < a->cfg.nendpoints; i++) {
        const ep_state *s = &a->ep[i];

        if (s->q.count > 0)
            say("%s: stopping with %u message%s unsent; %s lost", s->e->name,
                s->q.count, s->q.count == 1 ? "" : "s",
                s->q.count == 1 ? "it is" : "they are");
        sent += s->sent;
        failed += s->failed;
        dropped += s->dropped;
    }
    say("%s: %lu cycles, %lu records, %lu ignored, %lu events, %lu "
        "throttled, %lu summaries, %lu duplicates, %lu notices; %lu sent, %lu failed "
        "attempts, %lu dropped, %u unsent", word, cycles, a->records,
        a->ignored, a->events, a->throttled, a->summaries, a->duplicates, a->notices, sent,
        failed, dropped, lost);
    return lost;
}

/* ---- --test ----------------------------------------------------------- */

static int test_endpoints(agent *a)
{
    static vn_msg m;
    char body[300];
    size_t i;
    int bad = 0;

    for (i = 0; i < a->cfg.nendpoints; i++) {
        ep_state *s = &a->ep[i];
        vn_http_target t;
        vn_http_result r;
        size_t len, body_len;
        const char *p;
        int outcome;

        vn_snprintf(body, sizeof body, "vmsnotify %s on %s can reach the "
                    "endpoint %s (%s).", VN_VERSION, a->node, s->e->name,
                    vn_endpoint_type_name(s->e->type));
        vn_format_notice(&m, a->node, VN_PRIO_NORMAL, "vmsnotify test", body);
        len = encode_slot(s->e, &m);
        if (len == 0) {
            printf("FAIL  %s (%s): the message cannot be encoded\n",
                   s->e->name, vn_endpoint_type_name(s->e->type));
            bad++;
            continue;
        }
        fill_target(s->e, &t);
        p = slot_target(slot_buf, len, &t, &body_len);
        outcome = vn_http_post(&t, p, body_len, &r);
        scrub(r.message, s);
        if (outcome == VN_HTTP_SENT) {
            printf("ok    %s (%s): HTTP %d%s%s\n", s->e->name,
                   vn_endpoint_type_name(s->e->type), r.status,
                   r.tls_info[0] ? ", " : "", r.tls_info);
        } else {
            bad++;
            if (r.status != 0)
                printf("FAIL  %s (%s): HTTP %d on %s%s%s\n", s->e->name,
                       vn_endpoint_type_name(s->e->type), r.status, t.path,
                       r.message[0] ? ": " : "", r.message);
            else
                printf("FAIL  %s (%s): %s\n", s->e->name,
                       vn_endpoint_type_name(s->e->type), r.message);
        }
        fflush(stdout);
    }
    printf("%s: %d of %lu endpoints failed\n", bad ? "FAILED" : "ok", bad,
           (unsigned long) a->cfg.nendpoints);
    return bad == 0;
}

/* ---- starting --------------------------------------------------------- */

/* Tokens from their files, what each endpoint must keep out of the log,
   and its queue. 0, having said why, if the agent cannot start. */
static int prepare_endpoints(agent *a, int queues)
{
    size_t i;

    for (i = 0; i < a->cfg.nendpoints; i++) {
        vn_endpoint *e = &a->cfg.endpoint[i];
        ep_state *s = &a->ep[i];
        char why[160];
        const char *reason = "";

        s->e = e;
        if (a->cfg.token_file[i][0] != '\0') {
            if (a->dry_run) {
                strcpy(e->token, "dry-run");
            } else if (!read_token(a->cfg.token_file[i], e->token,
                                   sizeof e->token, &reason)) {
                say("not starting: endpoint %s: token_file %s %s", e->name,
                    a->cfg.token_file[i], reason);
                return 0;
            }
        }
        if (!vn_endpoint_check(e, why, sizeof why)) {
            say("not starting: endpoint %s: %s", e->name, why);
            return 0;
        }
#ifndef VN_WITH_TLS
        if (e->tls && !a->dry_run) {
            say("not starting: endpoint %s is https, but this image was "
                "built without TLS", e->name);
            return 0;
        }
#endif
        vn_snprintf(s->secret[0], sizeof s->secret[0], "%s", e->token);
        vn_snprintf(s->secret[1], sizeof s->secret[1], "%s", e->pass);
        if (e->user[0] != '\0') {
            char raw[64 + VN_EP_STR + 2];
            size_t n = (size_t) vn_snprintf(raw, sizeof raw, "%s:%s", e->user,
                                            e->pass);

            vn_base64((const unsigned char *) raw, n, s->secret[2]);
        }
        if (queues && !vn_queue_init(&s->q, a->cfg.queue_len, SLOT_MAX)) {
            say("not starting: cannot allocate a queue of %u x %lu bytes "
                "for endpoint %s", a->cfg.queue_len, (unsigned long) SLOT_MAX,
                e->name);
            return 0;
        }
    }
    return 1;
}

static void usage(void)
{
    printf("usage: vmsnotify CONFIG [--log FILE] [--stop-file FILE]\n"
           "                        [--position FILE] [--cycles N]\n"
           "                        [--drain SECONDS] [--dry-run]\n"
           "       vmsnotify CONFIG --test      send a test notice to "
           "every endpoint\n"
           "       vmsnotify --version\n");
}

int main(int argc, char **argv)
{
    static agent a;
    static char pos_default[VN_CONFIG_STR];
    const char *config_path = NULL;
    unsigned long cycles = 0, done = 0, drain_s = 15, interval_ms;
    vn_u64 now, next_cycle, drain_until, last_now;
    char text[400];
    int i, test = 0, bad_args = 0;
    size_t k;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("vmsnotify %s\n", VN_VERSION);
        return EXIT_SUCCESS;
    }
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cycles") == 0 && i + 1 < argc)
            cycles = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--drain") == 0 && i + 1 < argc)
            drain_s = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc)
            log_path = argv[++i];
        else if (strcmp(argv[i], "--stop-file") == 0 && i + 1 < argc)
            stop_path = argv[++i];
        else if (strcmp(argv[i], "--position") == 0 && i + 1 < argc)
            a.pos_path = argv[++i];
        else if (strcmp(argv[i], "--test") == 0)
            test = 1;
        else if (strcmp(argv[i], "--dry-run") == 0)
            a.dry_run = 1;
        else if (config_path == NULL && argv[i][0] != '-')
            config_path = argv[i];
        else
            bad_args = 1;
    }
    if (config_path == NULL || bad_args || (test && a.dry_run)) {
        usage();
        return EXIT_FAILURE;
    }
    if (!read_config(config_path, &a.cfg))
        return EXIT_FAILURE;
    if (a.cfg.nendpoints == 0 && !a.dry_run) {
        say("not starting: the configuration has no [endpoint]");
        return EXIT_FAILURE;
    }
    if (a.cfg.node[0] != '\0')
        vn_snprintf(a.node, sizeof a.node, "%s", a.cfg.node);
    else if (!vn_platform_node(a.node, sizeof a.node))
        strcpy(a.node, "UNKNOWN");
    if (!prepare_endpoints(&a, !test && !a.dry_run))
        return EXIT_FAILURE;

    if (test)
        return test_endpoints(&a) ? EXIT_SUCCESS : EXIT_FAILURE;

    if (a.pos_path == NULL) {
        default_pos_path(config_path, pos_default, sizeof pos_default);
        a.pos_path = pos_default;
    }
    load_positions(&a);
    vn_throttle_init(&a.thr);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    interval_ms = (unsigned long) a.cfg.interval_s * 1000;

    say("vmsnotify %s starting on %s: every %u s, %lu rules, queue %u%s",
        VN_VERSION, a.node, a.cfg.interval_s, (unsigned long) a.cfg.rules.n,
        a.cfg.queue_len, a.dry_run ? "; DRY RUN, nothing is sent" : "");
    for (k = 0; k < a.cfg.nendpoints; k++) {
        const vn_endpoint *e = &a.cfg.endpoint[k];

        say("endpoint %s: %s, %s://%s:%s%s%s%s", e->name,
            vn_endpoint_type_name(e->type), e->tls ? "https" : "http",
            e->host, e->port, e->base,
            e->min_priority > VN_PRIO_LOW ? ", from priority " : "",
            e->min_priority > VN_PRIO_LOW ? vn_prio_name(e->min_priority)
                                          : "");
#ifdef VN_WITH_TLS
        if (e->tls)
            say("endpoint %s: TLS through %s, CA %s", e->name,
                vn_tls_library(),
                e->cafile[0] ? e->cafile : "(system default)");
#endif
    }
    if (stop_path != NULL)
        say("to stop: create %s", stop_path);

    a.logs.opcom = a.cfg.opcom;
    a.logs.audit = a.cfg.audit;
    a.logs.opcom_file = a.cfg.opcom_file;
    a.logs.audit_file = a.cfg.audit_file;
    a.logs.opcom_pos = a.pos_given[0];
    a.logs.audit_pos = a.pos_given[1];
    a.logs.max_age_s = a.cfg.catchup_max_age_s;
    a.logs.max_records = a.cfg.catchup_max_records;
    a.logs_on = a.logs.opcom || a.logs.audit;
    vn_logs_open(&a.logs);
    if (a.logs_on)
        say("reading %s%s%s; position kept in %s%s",
            a.logs.opcom ? a.logs.opcom_file : "",
            a.logs.opcom && a.logs.audit ? ", " : "",
            a.logs.audit ? a.logs.audit_file : "", a.pos_path,
            a.pos_given[0][0] || a.pos_given[1][0] ? ""
                                                   : " (none saved yet)");
    else
        say("logs.opcom and logs.audit are both off: there is nothing "
            "to read");

    vn_snprintf(text, sizeof text, "vmsnotify %s has started on %s, reading "
                "%s%s%s.", VN_VERSION, a.node,
                a.logs.opcom ? "the operator log" : "",
                a.logs.opcom && a.logs.audit ? " and " : "",
                a.logs.audit ? "the audit journal" : "");
    notice(&a, VN_PRIO_LOW, "vmsnotify started", text);

    drain_until = vn_q32(0);
    next_cycle = last_now = vn_time_mono_ms();
    for (;;) {
        vn_u64 wake;

        /*
         * A clock that steps backwards -- set by hand, or by NTP
         * correcting a fast clock -- would leave every deadline in the
         * future by the size of the step (on VMS the interval clock is
         * time()). Read and send now instead.
         */
        now = vn_time_mono_ms();
        if (vn_qcmp(ms_after(now, 1000), last_now) < 0) {
            say("clock went back %lu s; reading now",
                ms_between(now, last_now) / 1000);
            next_cycle = now;
            for (k = 0; k < a.cfg.nendpoints; k++)
                a.ep[k].next_send = now;
            if (!vn_qzero(drain_until))
                drain_until = ms_after(now, drain_s * 1000);
        }
        last_now = now;

        if (stop_requested()) {
            say("stop requested");
            wind_up(&a);
            a.stopping = 1;
            send_due(&a);
            account(&a, "stopped", done);
            return EXIT_SUCCESS;
        }
        now = vn_time_mono_ms();
        if ((cycles == 0 || done < cycles) && vn_qcmp(now, next_cycle) >= 0) {
            cycle(&a);
            done++;
            next_cycle = ms_after(next_cycle, interval_ms);
            if (vn_qcmp(next_cycle, now) <= 0)      /* fell behind */
                next_cycle = ms_after(now, interval_ms);
            if (cycles != 0 && done == cycles) {
                wind_up(&a);
                drain_until = ms_after(now, drain_s * 1000);
            }
        }
        send_due(&a);

        now = vn_time_mono_ms();
        if (cycles != 0 && done >= cycles &&
            (waiting(&a) == 0 || vn_qcmp(now, drain_until) >= 0))
            return account(&a, "done", done) > 0 ? EXIT_FAILURE
                                                 : EXIT_SUCCESS;

        /* At most a second at a time, so a stop is seen within one. */
        wake = (cycles == 0 || done < cycles) ? next_cycle : drain_until;
        for (k = 0; k < a.cfg.nendpoints; k++)
            if (a.ep[k].q.count > 0 && vn_qcmp(a.ep[k].next_send, wake) < 0)
                wake = a.ep[k].next_send;
        if (vn_qcmp(wake, now) > 0) {
            unsigned long left = ms_between(now, wake);

            vn_sleep_ms((vn_u32) (left > 1000 ? 1000 : left));
        }
    }
}
