/*
 * test_http.c — host-side unit tests for examples/postman/http.c
 *
 * Build and run:
 *   cd tests/host && make test_http && ./test_http
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../../examples/postman/http.h"

static int failures = 0;
static int passes   = 0;

#define EXPECT_EQ_INT(name, expected, actual) do {                    \
    long _e = (long)(expected), _a = (long)(actual);                  \
    if (_e == _a) { passes++; printf("PASS: %s\n", name); }           \
    else { failures++; printf("FAIL: %s expected=%ld actual=%ld\n",   \
                              name, _e, _a); }                        \
} while (0)

#define EXPECT_EQ_STR(name, expected, actual) do {                    \
    if (strcmp((expected), (actual)) == 0) {                          \
        passes++; printf("PASS: %s\n", name);                         \
    } else {                                                          \
        failures++;                                                   \
        printf("FAIL: %s\n  expected: %s\n  actual:   %s\n",          \
               name, (expected), (actual));                           \
    }                                                                 \
} while (0)

#define EXPECT_EQ_MEM(name, expected, actual, len) do {               \
    if (memcmp((expected), (actual), (len)) == 0) {                   \
        passes++; printf("PASS: %s\n", name);                         \
    } else {                                                          \
        failures++; printf("FAIL: %s (memory mismatch)\n", name);     \
    }                                                                 \
} while (0)

static void test_parse_url(void)
{
    char host[256], path[512];
    uint16_t port;

    /* Basic https URL with default port */
    int rc = http_parse_url("https://example.com/foo/bar",
                            strlen("https://example.com/foo/bar"),
                            host, sizeof(host), &port,
                            path, sizeof(path));
    EXPECT_EQ_INT("parse_url: https default", 0, rc);
    EXPECT_EQ_STR("parse_url: host",          "example.com", host);
    EXPECT_EQ_INT("parse_url: port",          443, port);
    EXPECT_EQ_STR("parse_url: path",          "/foo/bar", path);

    /* Explicit port */
    rc = http_parse_url("https://api.example.com:8443/v1/endpoint",
                        strlen("https://api.example.com:8443/v1/endpoint"),
                        host, sizeof(host), &port,
                        path, sizeof(path));
    EXPECT_EQ_INT("parse_url: explicit port rc", 0, rc);
    EXPECT_EQ_STR("parse_url: explicit host",  "api.example.com", host);
    EXPECT_EQ_INT("parse_url: explicit port",  8443, port);
    EXPECT_EQ_STR("parse_url: explicit path",  "/v1/endpoint", path);

    /* No path → defaults to "/" */
    rc = http_parse_url("https://www.google.com",
                        strlen("https://www.google.com"),
                        host, sizeof(host), &port,
                        path, sizeof(path));
    EXPECT_EQ_INT("parse_url: no path rc",     0, rc);
    EXPECT_EQ_STR("parse_url: no path host",   "www.google.com", host);
    EXPECT_EQ_INT("parse_url: no path port",   443, port);
    EXPECT_EQ_STR("parse_url: no path path",   "/", path);

    /* Query string preserved */
    rc = http_parse_url("https://httpbin.org/get?x=1&y=two",
                        strlen("https://httpbin.org/get?x=1&y=two"),
                        host, sizeof(host), &port,
                        path, sizeof(path));
    EXPECT_EQ_INT("parse_url: query rc",   0, rc);
    EXPECT_EQ_STR("parse_url: query path", "/get?x=1&y=two", path);

    /* http:// default port 80 */
    rc = http_parse_url("http://example.com/",
                        strlen("http://example.com/"),
                        host, sizeof(host), &port,
                        path, sizeof(path));
    EXPECT_EQ_INT("parse_url: http rc",   0, rc);
    EXPECT_EQ_INT("parse_url: http port", 80, port);

    /* Errors */
    EXPECT_EQ_INT("parse_url: missing scheme",
                  -1,
                  http_parse_url("example.com/foo", 15,
                                 host, sizeof(host), &port,
                                 path, sizeof(path)));

    EXPECT_EQ_INT("parse_url: bad scheme",
                  -1,
                  http_parse_url("ftp://example.com/", 18,
                                 host, sizeof(host), &port,
                                 path, sizeof(path)));

    EXPECT_EQ_INT("parse_url: empty host",
                  -1,
                  http_parse_url("https:///foo", 12,
                                 host, sizeof(host), &port,
                                 path, sizeof(path)));

    /* Host buffer overflow */
    char tiny[4];
    EXPECT_EQ_INT("parse_url: host overflow",
                  -1,
                  http_parse_url("https://example.com/",
                                 strlen("https://example.com/"),
                                 tiny, sizeof(tiny), &port,
                                 path, sizeof(path)));
}

static void test_smoke(void)
{
    /* Placeholder so the harness builds and runs before Task 3. */
    printf("=== test_http smoke ===\n");
    EXPECT_EQ_INT("harness runs", 1, 1);
}

static void test_build_request(void)
{
    char out[4096];
    int n;

    /* GET with no body, no user headers */
    n = http_build_request("GET", "example.com", "/foo",
                           NULL, 0,
                           NULL, 0,
                           out, sizeof(out));
    const char *expected1 =
        "GET /foo HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    EXPECT_EQ_INT("build: GET rc", (int)strlen(expected1), n);
    EXPECT_EQ_STR("build: GET bytes", expected1, out);

    /* POST with body and Content-Type header */
    const char *body = "{\"k\":\"v\"}";
    n = http_build_request("POST", "api.example.com", "/v1/items",
                           "Content-Type: application/json\r\n",
                           strlen("Content-Type: application/json\r\n"),
                           body, strlen(body),
                           out, sizeof(out));
    const char *expected2 =
        "POST /v1/items HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "{\"k\":\"v\"}";
    EXPECT_EQ_INT("build: POST rc", (int)strlen(expected2), n);
    EXPECT_EQ_STR("build: POST bytes", expected2, out);

    /* GET with body set — body must be stripped */
    n = http_build_request("GET", "example.com", "/",
                           NULL, 0,
                           "should be ignored",
                           strlen("should be ignored"),
                           out, sizeof(out));
    const char *expected3 =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    EXPECT_EQ_INT("build: GET+body strip rc", (int)strlen(expected3), n);
    EXPECT_EQ_STR("build: GET+body strip bytes", expected3, out);

    /* User headers with LF-only separators are converted to CRLF */
    n = http_build_request("GET", "example.com", "/",
                           "X-One: a\nX-Two: b\n",
                           strlen("X-One: a\nX-Two: b\n"),
                           NULL, 0,
                           out, sizeof(out));
    const char *expected4 =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "X-One: a\r\n"
        "X-Two: b\r\n"
        "\r\n";
    EXPECT_EQ_INT("build: LF headers rc", (int)strlen(expected4), n);
    EXPECT_EQ_STR("build: LF headers bytes", expected4, out);

    /* User-supplied Host: is stripped (SNI mismatch guard) */
    n = http_build_request("GET", "real.example.com", "/",
                           "Host: fake.example.com\r\nX-Foo: bar\r\n",
                           strlen("Host: fake.example.com\r\nX-Foo: bar\r\n"),
                           NULL, 0,
                           out, sizeof(out));
    const char *expected5 =
        "GET / HTTP/1.1\r\n"
        "Host: real.example.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "X-Foo: bar\r\n"
        "\r\n";
    EXPECT_EQ_INT("build: strip Host rc", (int)strlen(expected5), n);
    EXPECT_EQ_STR("build: strip Host bytes", expected5, out);

    /* User-supplied User-Agent: suppresses ours */
    n = http_build_request("GET", "example.com", "/",
                           "User-Agent: Custom/1.0\r\n",
                           strlen("User-Agent: Custom/1.0\r\n"),
                           NULL, 0,
                           out, sizeof(out));
    const char *expected6 =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n"
        "User-Agent: Custom/1.0\r\n"
        "\r\n";
    EXPECT_EQ_INT("build: custom UA rc", (int)strlen(expected6), n);
    EXPECT_EQ_STR("build: custom UA bytes", expected6, out);

    /* Overflow */
    char tiny[32];
    n = http_build_request("GET", "example.com", "/very/long/path",
                           NULL, 0, NULL, 0, tiny, sizeof(tiny));
    EXPECT_EQ_INT("build: overflow", -1, n);
}

static void test_split_response(void)
{
    const char *raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "hello, world!";
    size_t raw_len = strlen(raw);

    const char *status; size_t status_len;
    const char *headers; size_t headers_len;
    const char *body; size_t body_len;

    int rc = http_split_response(raw, raw_len,
                                 &status, &status_len,
                                 &headers, &headers_len,
                                 &body, &body_len);
    EXPECT_EQ_INT("split: 200 rc", 0, rc);
    EXPECT_EQ_INT("split: status len", 15, (int)status_len);
    EXPECT_EQ_MEM("split: status",     "HTTP/1.1 200 OK", status, 15);
    EXPECT_EQ_INT("split: headers len", 43, (int)headers_len);
    EXPECT_EQ_INT("split: body len",    13, (int)body_len);
    EXPECT_EQ_MEM("split: body",        "hello, world!", body, 13);

    /* Empty body */
    const char *raw2 =
        "HTTP/1.1 204 No Content\r\n"
        "Connection: close\r\n"
        "\r\n";
    rc = http_split_response(raw2, strlen(raw2),
                             &status, &status_len,
                             &headers, &headers_len,
                             &body, &body_len);
    EXPECT_EQ_INT("split: 204 rc",         0,  rc);
    EXPECT_EQ_INT("split: 204 status len", 23, (int)status_len);
    EXPECT_EQ_INT("split: 204 body len",   0,  (int)body_len);

    /* No CRLF at all → error */
    rc = http_split_response("garbage no crlf", 15,
                             &status, &status_len,
                             &headers, &headers_len,
                             &body, &body_len);
    EXPECT_EQ_INT("split: no crlf", -1, rc);

    /* Has CRLF but no blank-line terminator → error */
    rc = http_split_response("HTTP/1.1 200 OK\r\nFoo: bar\r\n", 27,
                             &status, &status_len,
                             &headers, &headers_len,
                             &body, &body_len);
    EXPECT_EQ_INT("split: no blank line", -1, rc);

    /* Empty input → error */
    rc = http_split_response("", 0,
                             &status, &status_len,
                             &headers, &headers_len,
                             &body, &body_len);
    EXPECT_EQ_INT("split: empty", -1, rc);
}

int main(void)
{
    test_smoke();
    test_parse_url();
    test_build_request();
    test_split_response();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
