/*
 * vmsnotify tests: the configuration file, including the shipped example.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "config.h"
#include "recs.h"

static int parse(vn_config *c, const char *text, char *err)
{
    return vn_config_parse(c, text, strlen(text), err, 160);
}

static void bad(const char *text, const char *want)
{
    vn_config c;
    char err[160];

    CHECK(!parse(&c, text, err));
    CHECK_CONTAINS(err, want);
}

static void test_good(void)
{
    static vn_config c;
    char err[160];
    vn_log_rec r;
    const vn_rule *m;
    const vn_endpoint *e;

    CHECK(parse(&c,
        "# a comment\n"
        "! and another\n"
        "Interval = 30\n"
        "node = PROD1\n"
        "rules.defaults.to = home\n"
        "\n"
        "[endpoint home]\n"
        "type = gotify\n"
        "url = https://gotify.lan:8443/\n"
        "token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN\n"
        "[endpoint pager]\n"
        "type = ntfy\n"
        "url = http://ntfy.lan\n"
        "topic = vms\n"
        "user = u\n"
        "password = p w\n"
        "min_priority = high\n"
        "[rule noise]\n"
        "source = audit\n"
        "types = LOGFAIL\n"
        "remote = *192.0.2.10\n"
        "action = ignore\n"
        "[rule shadow]\n"
        "text = *SHADOW*\n"
        "priority = urgent\n"
        "to = pager, home\n"
        "throttle = 0\n", err));
    CHECK(err[0] == '\0');
    CHECK(c.interval_s == 30 && strcmp(c.node, "PROD1") == 0);
    CHECK(c.nendpoints == 2);
    e = vn_config_endpoint(&c, "HOME");
    CHECK(e != NULL && e->type == VN_EP_GOTIFY && e->tls && strcmp(e->port, "8443") == 0);
    CHECK(strcmp(c.token_file[0], "VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN") == 0);
    CHECK(e->token[0] == '\0');            /* the agent reads the file */
    e = vn_config_endpoint(&c, "pager");
    CHECK(e != NULL && strcmp(e->pass, "p w") == 0 && e->min_priority == VN_PRIO_HIGH);
    /* Two user rules, then the nine defaults with rules.defaults.to. */
    CHECK(c.rules.n == 11);
    CHECK(strcmp(c.rules.rule[2].name, "breakin") == 0);
    CHECK(strcmp(c.rules.rule[2].to, "home") == 0);
    CHECK(c.rules.rule[1].throttle_s == 0 && c.rules.rule[2].throttle_s == 300);

    CHECK(recs_audit(&r, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    m = vn_rules_match(&c.rules, &r);
    CHECK(m != NULL && strcmp(m->name, "noise") == 0 && m->action == VN_ACT_IGNORE);
    CHECK(recs_opcom(&r, "Message from user SYSTEM on X86VMS\n%SHADOW-I-COPYING, copy started"));
    m = vn_rules_match(&c.rules, &r);
    CHECK(m != NULL && strcmp(m->name, "shadow") == 0 && m->priority == VN_PRIO_URGENT);

    CHECK(parse(&c, "rules.defaults = no\nlogs.opcom = no\n"
                    "[endpoint w]\ntype = webhook\nurl = http://h/x\n", err));
    CHECK(c.rules.n == 0 && !c.opcom && c.audit);
}

static void test_bad(void)
{
    bad("[endpoint e]\ntype = slack\n", "line 2: type must be");
    bad("[endpoint e]\ntype = gotify\nurl = https://g\n", "endpoint e: gotify needs");
    bad("[endpoint e]\ntype = gotify\nurl = https://g/message?token=x\n", "line 3: url must not have a query");
    bad("[endpoint e]\ntype = gotify\nurl = https://g\ntoken = a\ntoken_file = b\n", "both given");
    bad("[endpoint e]\ntype = apprise\nurl = https://a\n", "apprise needs key");
    bad("[endpoint e]\ntype = ntfy\nurl = https://n\n", "ntfy needs a topic");
    bad("[endpoint e]\ntype = webhook\nurl = http://w\n[endpoint e]\n", "a second endpoint e");
    bad("[endpoint e]\ntype = webhook\nurl = http://w\n[rule r]\nto = nobody\n", "rule r: no endpoint called nobody");
    bad("[endpoint e]\ntype = webhook\nurl = http://w\n[rule r]\nseverity = loud\n", "line 5: severity must be");
    bad("[endpoint e]\ntype = webhook\nurl = http://w\n[rule r]\ncolour = red\n", "unknown rule setting colour");
    bad("[endpoint e]\ntype = webhook\nurl = http://w\n[group g]\n", "unknown section [group]");
    bad("[endpoint]\n", "a section needs a name");
    bad("[endpoint a b]\n", "a section needs a name");
    bad("interval = 0\n", "line 1: interval must be");
    bad("logs.opcom = maybe\n", "logs.opcom must be yes or no");
    bad("frequency = 10\n", "unknown setting frequency");
    bad("just words\n", "line 1: expected key = value");
    bad("node =\n", "node has no value");
    bad("logs.opcom = yes\n", "no [endpoint]");
    bad("logs.opcom = no\nlogs.audit = no\n[endpoint e]\ntype = webhook\nurl = http://w\n", "nothing to read");
    bad("rules.defaults.to = x\n[endpoint e]\ntype = webhook\nurl = http://w\n", "rules.defaults.to: no endpoint called x");
}

static void test_example(const char *path)
{
    static vn_config c;
    static char text[32768];
    char err[160];
    FILE *f = fopen(path, "rb");
    size_t n;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    CHECK(vn_config_parse(&c, text, n, err, sizeof err));
    if (err[0])
        printf("example: %s\n", err);
    CHECK(c.nendpoints == 1 && c.rules.n == 9);
    CHECK(strcmp(c.token_file[0], "VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN") == 0);
}

int main(int argc, char **argv)
{
    test_good();
    test_bad();
    test_example(argc > 1 ? argv[1] : "vmsnotify.conf.example");
    return check_summary("test_config");
}
