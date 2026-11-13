/*
 * vmsnotify tests: what the transport makes of a server's answer --
 * the outcome, Retry-After in both its forms, and the reason it gives
 * the log.
 */

#include <string.h>

#include "check.h"
#include "http.h"

static int parse(const char *resp, vn_http_result *r)
{
    memset(r, 0, sizeof *r);
    return vn_http_parse_response(resp, strlen(resp), r);
}

int main(void)
{
    vn_http_result r;
    unsigned long t;

    /* Delivered: Gotify echoes the message, which is not a reason. */
    CHECK(parse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Date: Fri, 13 Nov 2026 16:44:37 GMT\r\n\r\n"
                "{\"id\":7,\"message\":\"Login failure\",\"title\":\"X\"}",
                &r) == VN_HTTP_SENT);
    CHECK(r.status == 200 && r.message[0] == '\0' && r.retry_after_s == -1);
    CHECK(r.have_date && r.date_unix == 1794588277ul);
    CHECK(parse("HTTP/1.1 204 No Content\r\n\r\n", &r) == VN_HTTP_SENT);

    /* Gotify's 401: the description is the better of its two texts. */
    CHECK(parse("HTTP/1.1 401 Unauthorized\r\n\r\n"
                "{\"error\":\"Unauthorized\",\"errorCode\":401,"
                "\"errorDescription\":\"you need to provide a valid access "
                "token or user credentials to access this api\"}", &r)
          == VN_HTTP_REJECTED);
    CHECK(r.status == 401);
    CHECK(strncmp(r.message, "you need to provide a valid", 27) == 0);

    /* ntfy: "error"; a number before it under a like name is passed by. */
    CHECK(parse("HTTP/1.1 403 Forbidden\r\n\r\n{\"code\":40301,\"http\":403,"
                "\"error\":\"forbidden\",\"link\":\"https://ntfy.sh/docs\"}",
                &r) == VN_HTTP_REJECTED);
    CHECK(strcmp(r.message, "forbidden") == 0);
    CHECK(parse("HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":400,"
                "\"message\":\"bad \\\"type\\\"\"}", &r) == VN_HTTP_REJECTED);
    CHECK(strcmp(r.message, "bad \"type\"") == 0);

    /* Not JSON: the start of the body, made one printable line. */
    CHECK(parse("HTTP/1.1 404 Not Found\r\n\r\n<html>\r\n<head><title>404 "
                "Not Found</title></head>\x01\xff\n", &r) == VN_HTTP_REJECTED);
    CHECK(strcmp(r.message, "<html> <head><title>404 Not Found</title>"
                            "</head>") == 0);
    {
        char big[600];
        size_t n;

        strcpy(big, "HTTP/1.1 400 Bad Request\r\n\r\n");
        n = strlen(big);
        memset(big + n, 'x', 400);
        big[n + 400] = '\0';
        CHECK(parse(big, &r) == VN_HTTP_REJECTED);
        CHECK(strlen(r.message) == 150);
    }
    /* A chunked body starts with its length, which is no reason. */
    CHECK(parse("HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n"
                "9\r\nno topic\n\r\n0\r\n\r\n", &r) == VN_HTTP_REJECTED);
    CHECK(strncmp(r.message, "no topic", 8) == 0);
    CHECK(parse("HTTP/1.1 404 Not Found\r\n\r\n", &r) == VN_HTTP_REJECTED);
    CHECK(r.message[0] == '\0');

    /* Try later: 429, any 5xx, and nothing that is HTTP. */
    CHECK(parse("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 120\r\n"
                "\r\n", &r) == VN_HTTP_RETRY);
    CHECK(r.status == 503 && r.retry_after_s == 120);
    CHECK(parse("HTTP/1.1 429 Too Many Requests\r\n"
                "date: Fri, 13 Nov 2026 16:44:37 GMT\r\n"
                "retry-after: Fri, 13 Nov 2026 16:45:07 GMT\r\n\r\n"
                "{\"error\":\"too many requests\"}", &r) == VN_HTTP_RETRY);
    CHECK(r.retry_after_s == 30);
    CHECK(strcmp(r.message, "too many requests") == 0);
    /* A date already past is "now"; a date with no Date to compare, none. */
    CHECK(parse("HTTP/1.1 503 x\r\nDate: Fri, 13 Nov 2026 16:44:37 GMT\r\n"
                "Retry-After: Fri, 13 Nov 2026 16:00:00 GMT\r\n\r\n", &r)
          == VN_HTTP_RETRY && r.retry_after_s == 0);
    CHECK(parse("HTTP/1.1 503 x\r\n"
                "Retry-After: Fri, 13 Nov 2026 16:00:00 GMT\r\n\r\n", &r)
          == VN_HTTP_RETRY && r.retry_after_s == -1);
    CHECK(parse("HTTP/1.1 500 Internal Server Error\r\n\r\n", &r)
          == VN_HTTP_RETRY && r.retry_after_s == -1);
    CHECK(parse("", &r) == VN_HTTP_RETRY && r.status == 0);
    CHECK(strcmp(r.message, "no response") == 0);
    CHECK(parse("SSH-2.0-OpenSSH_9.6\r\n", &r) == VN_HTTP_RETRY);
    CHECK(strcmp(r.message, "response is not HTTP") == 0);

    CHECK(vn_http_parse_date("Thu, 01 Jan 1970 00:00:00 GMT", &t) && t == 0);
    CHECK(!vn_http_parse_date("yesterday", &t));

    return check_summary("test_http");
}
