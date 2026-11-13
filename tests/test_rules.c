/*
 * vmsnotify tests: rules, throttling and formatting, on records made by
 * the real parsers.
 */

#include <stdio.h>
#include <string.h>

#include "check.h"
#include "format.h"
#include "recs.h"
#include "rules.h"
#include "throttle.h"

static const char *matched(const vn_ruleset *rs, const vn_log_rec *r)
{
    const vn_rule *m = vn_rules_match(rs, r);

    return m == NULL ? "(none)" : m->name;
}

static void test_wildcards(void)
{
    CHECK(vn_wildcard_match("SYS*", "SYSTEM"));
    CHECK(vn_wildcard_match("sys*", "SYSTEM"));
    CHECK(vn_wildcard_match("S%STEM", "SYSTEM"));
    CHECK(!vn_wildcard_match("S%TEM", "SYSTEM"));
    CHECK(vn_wildcard_match("*192.168.0.*", "SSH_PASSWORD:192.168.0.131"));
    CHECK(vn_wildcard_match("*", ""));
    CHECK(!vn_wildcard_match("X", ""));
}

static void test_defaults(void)
{
    vn_ruleset rs;
    vn_log_rec r;

    memset(&rs, 0, sizeof rs);
    CHECK(vn_rules_add_defaults(&rs));

    CHECK(recs_audit(&r, 3, "ROOT", NULL, NULL, "FTA6761:"));
    CHECK(strcmp(matched(&rs, &r), "breakin") == 0);
    CHECK(vn_rules_match(&rs, &r)->priority == VN_PRIO_URGENT);

    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    CHECK(strcmp(matched(&rs, &r), "login-failure") == 0);
    CHECK(vn_rules_match(&rs, &r)->priority == VN_PRIO_HIGH);

    CHECK(recs_audit(&r, 11, "SYSTEM", NULL, NULL, NULL));     /* SYSUAF */
    CHECK(strcmp(matched(&rs, &r), "authorization") == 0);
    CHECK(recs_audit(&r, 1, "SYSTEM", NULL, NULL, NULL));      /* SERVER */
    CHECK(strcmp(matched(&rs, &r), "auditing") == 0);
    CHECK(recs_audit(&r, 21, "SYSTEM", NULL, NULL, NULL));     /* SYSTIME */
    CHECK(strcmp(matched(&rs, &r), "privileged") == 0);
    CHECK(recs_audit(&r, 22, "SYSTEM", NULL, NULL, NULL));     /* SYSGEN */
    CHECK(strcmp(matched(&rs, &r), "privileged") == 0);
    CHECK(recs_audit(&r, 10, "IAIN", NULL, NULL, NULL));       /* ACCESS */
    CHECK(strcmp(matched(&rs, &r), "(none)") == 0);

    /* Quiet: a login, a logout. */
    CHECK(recs_audit(&r, 6, "IAIN", NULL, NULL, "FTA5:"));
    CHECK(strcmp(matched(&rs, &r), "(none)") == 0);
    CHECK(recs_audit(&r, 7, "IAIN", NULL, NULL, "FTA5:"));
    CHECK(strcmp(matched(&rs, &r), "(none)") == 0);

    /* OPCOM: an error, a warning, a request, and the hourly time stamp. */
    CHECK(recs_opcom(&r, "Message from user SYSTEM on X86VMS\n"
                         "%MOUNT-E-OPENIN, error opening DKA200:"));
    CHECK(strcmp(matched(&rs, &r), "opcom-error") == 0);
    CHECK(recs_opcom(&r, "Message from user SYSTEM on X86VMS\n"
                         "%SYSTEM-W-NOSUCHDEV, no such device available"));
    CHECK(strcmp(matched(&rs, &r), "opcom-warning") == 0);
    CHECK(vn_rules_match(&rs, &r)->priority == VN_PRIO_NORMAL);
    CHECK(recs_opcom(&r, "Request 3, from user IAIN on X86VMS\n"
                         "_X86VMS$FTA5:, Please mount tape VMS001"));
    CHECK(strcmp(matched(&rs, &r), "opcom-request") == 0);
    CHECK(recs_opcom(&r, "Logfile time stamp"));
    CHECK(strcmp(matched(&rs, &r), "(none)") == 0);
    CHECK(recs_opcom(&r, "Message from user IAIN on X86VMS\nhello"));
    CHECK(strcmp(matched(&rs, &r), "(none)") == 0);
}

static void test_user_rules(void)
{
    vn_ruleset rs;
    vn_rule u;
    vn_log_rec r;

    memset(&rs, 0, sizeof rs);
    /* Silence login failures from one monitoring host, ahead of the
       defaults. */
    vn_rule_init(&u, "monitor-noise");
    u.source = VN_LOG_AUDIT;
    strcpy(u.types, "logfail");           /* type names are case-blind */
    strcpy(u.remote, "*192.0.2.10");
    u.action = VN_ACT_IGNORE;
    CHECK(vn_rules_add(&rs, &u));
    /* Anything mentioning SHADOW, urgently, to one endpoint. */
    vn_rule_init(&u, "shadow");
    u.source = VN_LOG_OPCOM;
    strcpy(u.text, "*SHADOW*");
    u.priority = VN_PRIO_URGENT;
    strcpy(u.to, "home, pager");
    CHECK(vn_rules_add(&rs, &u));
    CHECK(vn_rules_add_defaults(&rs));

    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    CHECK(vn_rules_match(&rs, &r)->action == VN_ACT_IGNORE);
    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.99", NULL));
    CHECK(strcmp(matched(&rs, &r), "login-failure") == 0);

    CHECK(recs_opcom(&r, "Message from user SYSTEM on X86VMS\n"
                         "%SHADOW-I-COPYING, shadow set DSA1: copy started"));
    CHECK(strcmp(matched(&rs, &r), "shadow") == 0);
    CHECK(vn_rule_sends_to(vn_rules_match(&rs, &r), "pager"));
    CHECK(vn_rule_sends_to(vn_rules_match(&rs, &r), "HOME"));
    CHECK(!vn_rule_sends_to(vn_rules_match(&rs, &r), "apprise"));
    CHECK(vn_rule_sends_to(&rs.rule[rs.n - 1], "anything"));

    CHECK(vn_prio_parse("High") == VN_PRIO_HIGH);
    CHECK(vn_prio_parse("loud") == 0);
    CHECK(strcmp(vn_prio_name(VN_PRIO_URGENT), "urgent") == 0);
}

static void test_throttle(void)
{
    vn_throttle t;
    vn_rule rule;
    vn_summary s[4];
    vn_log_rec r;
    char key[VN_THR_KEY];
    int sent = 0, i;

    vn_throttle_init(&t);
    vn_rule_init(&rule, "login-failure");
    rule.priority = VN_PRIO_HIGH;

    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    vn_throttle_key(&r, key, sizeof key);
    CHECK(strcmp(key, "ROOT from 192.0.2.10") == 0);

    /* Twenty failures in a minute: one sent, nineteen counted. */
    for (i = 0; i < 20; i++)
        sent += vn_throttle_admit(&t, &rule, key, "X86VMS: Login failure", 1000 + (unsigned long) i * 3, 0);
    CHECK(sent == 1);
    CHECK(vn_throttle_due(&t, 1100, 0, s, 4) == 0);       /* window open */
    /* Another key is its own group. */
    CHECK(vn_throttle_admit(&t, &rule, "OTHER", "x", 1101, 0) == 1);
    /* At the end of the window, one summary. */
    CHECK(vn_throttle_due(&t, 1300, 0, s, 4) == 1);
    CHECK(s[0].count == 19);
    CHECK(strcmp(s[0].rule, "login-failure") == 0);
    CHECK(s[0].priority == VN_PRIO_HIGH);
    CHECK(vn_throttle_due(&t, 1300, 0, s, 4) == 0);       /* only once */
    /* "OTHER" ended with none counted: freed, no summary. */
    CHECK(vn_throttle_due(&t, 1500, 0, s, 4) == 0);
    /* A new event after the window is sent and opens a new one. */
    CHECK(vn_throttle_admit(&t, &rule, key, "x", 1301, 0) == 1);
    CHECK(vn_throttle_admit(&t, &rule, key, "x", 1302, 0) == 0);
    /* Flush at shutdown gives it now. */
    CHECK(vn_throttle_due(&t, 1303, 1, s, 4) == 1 && s[0].count == 1);

    /* An event whose window ended before due() ran: its summary is kept,
       and the event opens the next window. */
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 2000, 0) == 1);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 2001, 0) == 0);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 2400, 0) == 1);
    CHECK(vn_throttle_due(&t, 2401, 0, s, 4) == 1 && s[0].count == 1);

    /* throttle_s 0: everything is sent. */
    rule.throttle_s = 0;
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 3000, 0) == 1);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 3000, 0) == 1);

    /* A full table never suppresses an event it cannot track. */
    rule.throttle_s = 300;
    vn_throttle_init(&t);
    for (i = 0; i < VN_THR_MAX; i++) {
        char k[16];

        sprintf(k, "K%d", i);
        CHECK(vn_throttle_admit(&t, &rule, k, "x", 5000, 0) == 1);
    }
    CHECK(vn_throttle_admit(&t, &rule, "NEW", "x", 5001, 0) == 1);
    CHECK(vn_throttle_admit(&t, &rule, "NEW", "x", 5002, 0) == 1);
}

/* Sets a record's time to Unix seconds, as the parsers would have read it. */
static void recs_set_secs(vn_log_rec *r, unsigned long secs)
{
    r->time_ns = vn_qmul(vn_q32((vn_u32) secs), 1000000000u);
}

/* The Alpha's two records for one failed SSH login (findings, "Alpha"). */
static void alpha_pair(vn_log_rec *a, vn_log_rec *b, unsigned long secs)
{
    CHECK(recs_audit(a, 5, "IAIN", "iain", "192.168.0.131", NULL));
    CHECK(recs_audit(b, 5, "SSH$SSH", "IAIN", "SSH_PASSWORD:192.168.0.131", NULL));
    recs_set_secs(a, secs);
    recs_set_secs(b, secs);
}

static void test_throttle_key(void)
{
    vn_log_rec a, b, r, o;
    char ka[VN_THR_KEY], kb[VN_THR_KEY];

    alpha_pair(&a, &b, 1000);
    vn_throttle_key(&a, ka, sizeof ka);
    vn_throttle_key(&b, kb, sizeof kb);
    CHECK(strcmp(ka, "IAIN from 192.168.0.131") == 0);
    CHECK(strcmp(kb, "IAIN from 192.168.0.131") == 0);
    /* The rules still see what the records say. */
    CHECK(strcmp(vn_rec_user(&a), "IAIN") == 0);
    CHECK(strcmp(vn_rec_user(&b), "SSH$SSH") == 0);
    CHECK(strcmp(vn_rec_remote(&b), "SSH_PASSWORD:192.168.0.131") == 0);

    /* x86 and IA64: one record, with a terminal. */
    CHECK(recs_audit(&r, 5, "IAIN", "IAIN", "192.168.0.131", "TNA1:"));
    vn_throttle_key(&r, ka, sizeof ka);
    CHECK(strcmp(ka, "IAIN from 192.168.0.131") == 0);
    /* No remote user: the user; no remote node: no "from". */
    CHECK(recs_audit(&r, 5, "system", NULL, NULL, "FTA1:"));
    vn_throttle_key(&r, ka, sizeof ka);
    CHECK(strcmp(ka, "SYSTEM") == 0);
    /* An operator message has no remote user attribute to consult. */
    CHECK(recs_opcom(&o, "Message from user SYSTEM on X86VMS\n%MOUNT-F-MEDOFL, offline"));
    vn_throttle_key(&o, ka, sizeof ka);
    CHECK(strcmp(ka, "SYSTEM") == 0);

    /* The prefix rule. */
    CHECK(strcmp(vn_throttle_place("SSH_PASSWORD:192.168.0.131"), "192.168.0.131") == 0);
    CHECK(strcmp(vn_throttle_place("SSH_PASSWORD:fe80::1"), "fe80::1") == 0);
    CHECK(strcmp(vn_throttle_place("FTP_C0A80083"), "FTP_C0A80083") == 0);
    CHECK(strcmp(vn_throttle_place("192.168.0.5"), "192.168.0.5") == 0);
    CHECK(strcmp(vn_throttle_place("fe80::1"), "fe80::1") == 0);
    CHECK(strcmp(vn_throttle_place("2001:db8::1"), "2001:db8::1") == 0);
    CHECK(strcmp(vn_throttle_place("abcd::1"), "abcd::1") == 0);
    CHECK(strcmp(vn_throttle_place("BEEF:1"), "BEEF:1") == 0);   /* all hex */
    CHECK(strcmp(vn_throttle_place("HOST:1"), "1") == 0);
    CHECK(strcmp(vn_throttle_place(""), "") == 0);
    CHECK(strcmp(vn_throttle_place(":x"), ":x") == 0);
}

static void test_throttle_twins(void)
{
    vn_throttle t;
    vn_rule rule, other;
    vn_summary s[4];
    vn_log_rec a, b, c, d, e;
    char ka[VN_THR_KEY], kb[VN_THR_KEY], ke[VN_THR_KEY];

    vn_rule_init(&rule, "login-failure");
    rule.throttle_s = 300;

    /* The Alpha pair: one sent, the twin dropped and not counted, so the
       window's end gives no summary. */
    vn_throttle_init(&t);
    alpha_pair(&a, &b, 1000);
    vn_throttle_key(&a, ka, sizeof ka);
    vn_throttle_key(&b, kb, sizeof kb);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 50, vn_throttle_rec_s(&a)) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, kb, "x", 50, vn_throttle_rec_s(&b)) == VN_THR_DUP);
    CHECK(vn_throttle_due(&t, 400, 0, s, 4) == 0);
    CHECK(vn_throttle_due(&t, 400, 1, s, 4) == 0);

    /* Two separate failures 10 s apart: the second is counted, and its
       twin is not; "1 more" follows. */
    vn_throttle_init(&t);
    alpha_pair(&a, &b, 1000);
    alpha_pair(&c, &d, 1010);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 50, vn_throttle_rec_s(&a)) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, kb, "x", 50, vn_throttle_rec_s(&b)) == VN_THR_DUP);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 60, vn_throttle_rec_s(&c)) == VN_THR_COUNTED);
    CHECK(vn_throttle_admit(&t, &rule, kb, "x", 60, vn_throttle_rec_s(&d)) == VN_THR_DUP);
    CHECK(vn_throttle_due(&t, 400, 0, s, 4) == 1);
    CHECK(s[0].count == 1);

    /* Throttle 0 sends every event, but still not the twin. */
    rule.throttle_s = 0;
    vn_throttle_init(&t);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 50, vn_throttle_rec_s(&a)) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, kb, "x", 50, vn_throttle_rec_s(&b)) == VN_THR_DUP);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 60, vn_throttle_rec_s(&c)) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, kb, "x", 60, vn_throttle_rec_s(&d)) == VN_THR_DUP);
    CHECK(vn_throttle_due(&t, 400, 1, s, 4) == 0);

    /* Different people from one address are different groups. */
    rule.throttle_s = 300;
    vn_throttle_init(&t);
    CHECK(recs_audit(&e, 5, "SSH$SSH", "BOB", "SSH_PASSWORD:192.168.0.131", NULL));
    recs_set_secs(&e, 1000);
    vn_throttle_key(&e, ke, sizeof ke);
    CHECK(strcmp(ke, "BOB from 192.168.0.131") == 0);
    CHECK(vn_throttle_admit(&t, &rule, ka, "x", 50, 1000) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, ke, "x", 50, 1000) == VN_THR_SEND);

    /* Within 2 s is a twin, 3 s is not; unknown time never is. */
    vn_throttle_init(&t);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 50, 1000) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 50, 1002) == VN_THR_DUP);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 50, 1003) == VN_THR_COUNTED);
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 50, 0) == VN_THR_COUNTED);
    CHECK(vn_throttle_due(&t, 400, 0, s, 4) == 1 && s[0].count == 2);

    /* Another rule's event is not its twin. */
    vn_throttle_init(&t);
    vn_rule_init(&other, "other");
    CHECK(vn_throttle_admit(&t, &rule, "K", "x", 50, 1000) == VN_THR_SEND);
    CHECK(vn_throttle_admit(&t, &other, "K", "x", 50, 1000) == VN_THR_SEND);
}

static void test_format(void)
{
    vn_ruleset rs;
    vn_log_rec r;
    vn_msg m;
    vn_summary s;
    char when[40];

    memset(&rs, 0, sizeof rs);
    vn_rules_add_defaults(&rs);

    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    vn_format_time(&r, when, sizeof when);
    CHECK(strcmp(when, "2026-11-13 16:44:37 UTC") == 0);
    vn_format_event(&m, "X86VMS", vn_rules_match(&rs, &r), &r);
    CHECK(strcmp(m.title, "X86VMS: Login failure: remote user ROOT from "
                          "SSH_PASSWORD:192.0.2.10") == 0);
    CHECK_CONTAINS(m.body, "Event: LOGFAIL\n");
    CHECK_CONTAINS(m.body, "User: SSH$SSH\n");
    CHECK_CONTAINS(m.body, "Remote user: ROOT\n");
    CHECK_CONTAINS(m.body, "Time: 2026-11-13 16:44:37 UTC\n");
    CHECK_CONTAINS(m.body, "Rule: login-failure\n");
    CHECK(m.priority == VN_PRIO_HIGH && m.rec == &r && m.kind == VN_MSG_EVENT);

    CHECK(recs_opcom(&r, "Request 3, from user IAIN on X86VMS\n"
                         "_X86VMS$FTA5:, Please mount tape VMS001"));
    vn_format_event(&m, "X86VMS", vn_rules_match(&rs, &r), &r);
    CHECK(strcmp(m.title, "X86VMS: Request 3: _X86VMS$FTA5:, Please mount tape VMS001") == 0);
    CHECK_CONTAINS(m.body, "Request 3, from user IAIN on X86VMS\n_X86VMS$FTA5:");

    CHECK(recs_opcom(&r, "Message from user SYSTEM on X86VMS\n"
                         "%MOUNT-E-OPENIN, error opening DKA200:"));
    vn_format_event(&m, "X86VMS", vn_rules_match(&rs, &r), &r);
    CHECK(strcmp(m.title, "X86VMS: %MOUNT-E-OPENIN, error opening DKA200:") == 0);

    memset(&s, 0, sizeof s);
    strcpy(s.rule, "login-failure");
    strcpy(s.key, "SSH$SSH from SSH_PASSWORD:192.0.2.10");
    strcpy(s.label, "X86VMS: Login failure: remote user ROOT");
    s.count = 19;
    s.window_s = 300;
    s.priority = VN_PRIO_HIGH;
    vn_format_summary(&m, "X86VMS", &s);
    CHECK(strcmp(m.title, "X86VMS: 19 more: Login failure: remote user ROOT") == 0);
    CHECK_CONTAINS(m.body, "19 more events matched rule login-failure for "
                           "SSH$SSH from SSH_PASSWORD:192.0.2.10 within 300 s");
    CHECK(m.kind == VN_MSG_SUMMARY && m.count == 19 && m.rec == NULL);

    vn_format_notice(&m, "X86VMS", VN_PRIO_LOW, "vmsnotify started", "Watching both logs.");
    CHECK(strcmp(m.title, "X86VMS: vmsnotify started") == 0);
    CHECK(m.rule[0] == '\0' && m.to[0] == '\0');
}

int main(void)
{
    test_wildcards();
    test_defaults();
    test_user_rules();
    test_throttle();
    test_throttle_key();
    test_throttle_twins();
    test_format();
    return check_summary("test_rules");
}
