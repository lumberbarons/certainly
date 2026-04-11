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

int main(void)
{
    test_smoke();
    test_parse_url();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
