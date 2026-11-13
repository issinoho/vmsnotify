/*
 * vmsnotify tests: what each endpoint sends.
 *
 * The payloads are compared byte for byte with tests/golden/. A golden
 * payload changes only on purpose: `make golden` rewrites them, then read
 * the diff. Each golden file is the request line's path, the extra
 * headers, a blank line, and the body.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "endpoint.h"
#include "format.h"
#include "recs.h"
#include "rules.h"

static const char *golden_dir;
static int write_golden;

static void endpoint(vn_endpoint *e, const char *type, const char *url)
{
    char err[120];

    memset(e, 0, sizeof *e);
    strcpy(e->name, type);
    CHECK(vn_endpoint_set_type(e, type));
    CHECK(vn_endpoint_set_url(e, url, err, sizeof err));
}

/* Encodes m for e and compares with golden/<name>. */
static void golden(const char *name, const vn_endpoint *e, const vn_msg *m)
{
    static char body[16384], want[20000];
    char path[512], got[20000];
    vn_request req;
    FILE *f;
    size_t n;

    CHECK(vn_endpoint_encode(e, m, body, sizeof body, &req));
    n = (size_t) snprintf(got, sizeof got, "POST %s\nContent-Type: %s\n%s\n",
                          req.path, req.content_type, req.headers);
    memcpy(got + n, body, req.body_len);
    n += req.body_len;
    got[n++] = '\n';
    got[n] = '\0';
    snprintf(path, sizeof path, "%s/%s", golden_dir, name);
    if (write_golden) {
        f = fopen(path, "wb");
        CHECK(f != NULL);
        if (f) {
            fwrite(got, 1, n, f);
            fclose(f);
        }
        return;
    }
    f = fopen(path, "rb");
    CHECK(f != NULL);
    if (f == NULL)
        return;
    want[fread(want, 1, sizeof want - 1, f)] = '\0';
    fclose(f);
    if (strcmp(got, want) != 0) {
        check_count++;
        check_failures++;
        printf("FAIL  %s differs from the encoder's output:\n%s\n", path, got);
    } else {
        check_count++;
    }
}

static void test_urls(void)
{
    vn_endpoint e;
    char err[120];

    memset(&e, 0, sizeof e);
    CHECK(vn_endpoint_set_url(&e, "https://gotify.lan", err, sizeof err));
    CHECK(e.tls && strcmp(e.host, "gotify.lan") == 0 && strcmp(e.port, "443") == 0 &&
          e.base[0] == '\0');
    CHECK(vn_endpoint_set_url(&e, "http://192.168.0.218:8080/apprise/", err, sizeof err));
    CHECK(!e.tls && strcmp(e.host, "192.168.0.218") == 0 && strcmp(e.port, "8080") == 0 &&
          strcmp(e.base, "/apprise") == 0);
    CHECK(!vn_endpoint_set_url(&e, "ftp://x", err, sizeof err));
    CHECK(!vn_endpoint_set_url(&e, "https://:443/", err, sizeof err));
    CHECK(!vn_endpoint_set_url(&e, "https://h:99999/", err, sizeof err));
    CHECK(!vn_endpoint_set_url(&e, "https://h:x/", err, sizeof err));
    /* No secrets in a URL: it would be logged. */
    CHECK(!vn_endpoint_set_url(&e, "https://g.lan/message?token=abc", err, sizeof err));
    CHECK_CONTAINS(err, "token");

    CHECK(vn_endpoint_set_type(&e, "Gotify") && e.type == VN_EP_GOTIFY);
    CHECK(!vn_endpoint_set_type(&e, "slack"));
    e.token[0] = '\0';
    CHECK(!vn_endpoint_check(&e, err, sizeof err));
    CHECK_CONTAINS(err, "token");
    strcpy(e.token, "AbCdEf");
    CHECK(vn_endpoint_check(&e, err, sizeof err));
    CHECK(vn_endpoint_set_type(&e, "ntfy"));
    CHECK(!vn_endpoint_check(&e, err, sizeof err));     /* no topic */
    strcpy(e.topic, "vms");
    strcpy(e.user, "u");
    CHECK(!vn_endpoint_check(&e, err, sizeof err));     /* token and user */
}

static void test_scales(void)
{
    char b[16];

    CHECK(vn_gotify_priority(VN_PRIO_LOW) == 2 && vn_gotify_priority(VN_PRIO_URGENT) == 10);
    CHECK(vn_ntfy_priority(VN_PRIO_NORMAL) == 3 && vn_ntfy_priority(VN_PRIO_HIGH) == 4);
    CHECK(strcmp(vn_apprise_type(VN_PRIO_NORMAL), "info") == 0);
    CHECK(strcmp(vn_apprise_type(VN_PRIO_URGENT), "failure") == 0);
    /* RFC 4648's test vectors. */
    vn_base64((const unsigned char *) "", 0, b);       CHECK(strcmp(b, "") == 0);
    vn_base64((const unsigned char *) "f", 1, b);      CHECK(strcmp(b, "Zg==") == 0);
    vn_base64((const unsigned char *) "fo", 2, b);     CHECK(strcmp(b, "Zm8=") == 0);
    vn_base64((const unsigned char *) "foo", 3, b);    CHECK(strcmp(b, "Zm9v") == 0);
    vn_base64((const unsigned char *) "foob", 4, b);   CHECK(strcmp(b, "Zm9vYg==") == 0);
    vn_base64((const unsigned char *) "foobar", 6, b); CHECK(strcmp(b, "Zm9vYmFy") == 0);
}

static void test_payloads(void)
{
    vn_ruleset rs;
    vn_log_rec audit, opcom;
    vn_msg ev, op, sum;
    vn_summary s;
    vn_endpoint g, a, n, w;

    memset(&rs, 0, sizeof rs);
    vn_rules_add_defaults(&rs);
    CHECK(recs_audit(&audit, 5, "SSH$SSH", "ROOT", "SSH_PASSWORD:192.0.2.10", NULL));
    vn_format_event(&ev, "X86VMS", vn_rules_match(&rs, &audit), &audit);
    /* 8-bit text, a quote and a backslash, as an OPCOM message can hold. */
    CHECK(recs_opcom(&opcom, "Message from user SYSTEM on X86VMS\n"
                             "%MOUNT-E-OPENIN, error opening \"DKA200:[CAF\xc9]\\x\""));
    vn_format_event(&op, "X86VMS", vn_rules_match(&rs, &opcom), &opcom);
    memset(&s, 0, sizeof s);
    strcpy(s.rule, "login-failure");
    strcpy(s.key, "SSH$SSH from SSH_PASSWORD:192.0.2.10");
    strcpy(s.label, ev.title);
    s.count = 19;
    s.window_s = 300;
    s.priority = VN_PRIO_HIGH;
    vn_format_summary(&sum, "X86VMS", &s);

    endpoint(&g, "gotify", "https://gotify.lan");
    strcpy(g.token, "AkY8Tz3bQ.Q4x7p");
    endpoint(&a, "apprise", "http://192.168.0.218:8000");
    strcpy(a.key, "vms");
    strcpy(a.tag, "ops");
    strcpy(a.user, "notify");
    strcpy(a.pass, "s3cret");
    endpoint(&n, "ntfy", "https://ntfy.lan/base");
    strcpy(n.topic, "openvms");
    strcpy(n.token, "tk_abc");
    endpoint(&w, "webhook", "http://nodered.lan:1880/vms");

    golden("gotify-event.txt", &g, &ev);
    golden("gotify-opcom.txt", &g, &op);
    golden("apprise-event.txt", &a, &ev);
    golden("apprise-summary.txt", &a, &sum);
    golden("ntfy-event.txt", &n, &ev);
    golden("ntfy-opcom.txt", &n, &op);
    golden("webhook-event.txt", &w, &ev);
    golden("webhook-summary.txt", &w, &sum);
}

static void test_header_safety(void)
{
    vn_endpoint n;
    vn_msg m;
    vn_request req;
    char body[4096];

    endpoint(&n, "ntfy", "https://ntfy.lan");
    strcpy(n.topic, "t");
    vn_format_notice(&m, "X86VMS", VN_PRIO_NORMAL, "a\r\nX-Injected: 1\xe9", "b");
    CHECK(vn_endpoint_encode(&n, &m, body, sizeof body, &req));
    CHECK(strstr(req.headers, "\r\nX-Injected") == NULL);
    CHECK_CONTAINS(req.headers, "Title: X86VMS: a  X-Injected: 1?\r\n");
    /* Too small a buffer is refused, not sent cut short. */
    endpoint(&n, "gotify", "https://g.lan");
    strcpy(n.token, "t");
    CHECK(!vn_endpoint_encode(&n, &m, body, 20, &req));
}

int main(int argc, char **argv)
{
    golden_dir = argc > 1 ? argv[1] : "tests/golden";
    write_golden = argc > 2 && strcmp(argv[2], "--write") == 0;
    test_urls();
    test_scales();
    test_payloads();
    test_header_safety();
    return check_summary(write_golden ? "test_endpoint (golden written)" : "test_endpoint");
}
