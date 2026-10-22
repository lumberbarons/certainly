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

static void test_decode_chunked(void)
{
    char out[4096];
    int n;

    /* Simple two-chunk body */
    const char *in1 =
        "5\r\n"
        "Hello\r\n"
        "6\r\n"
        " World\r\n"
        "0\r\n"
        "\r\n";
    n = http_decode_chunked(in1, strlen(in1), out, sizeof(out));
    EXPECT_EQ_INT("chunked: two chunks rc", 11, n);
    if (n == 11) {
        out[n] = '\0';
        EXPECT_EQ_STR("chunked: two chunks str", "Hello World", out);
    }

    /* Single hex-letter chunk (the Anthropic-style 0xea case) */
    const char *in2 =
        "a\r\n"
        "0123456789\r\n"
        "0\r\n"
        "\r\n";
    n = http_decode_chunked(in2, strlen(in2), out, sizeof(out));
    EXPECT_EQ_INT("chunked: hex len rc", 10, n);

    /* Chunk extension after hex length */
    const char *in3 =
        "5; foo=bar\r\n"
        "Hello\r\n"
        "0\r\n"
        "\r\n";
    n = http_decode_chunked(in3, strlen(in3), out, sizeof(out));
    EXPECT_EQ_INT("chunked: extension rc", 5, n);

    /* Missing terminator → error */
    const char *in4 = "5\r\nHello\r\n";
    n = http_decode_chunked(in4, strlen(in4), out, sizeof(out));
    EXPECT_EQ_INT("chunked: no terminator", -1, n);

    /* Malformed hex → error */
    const char *in5 = "xyz\r\nHello\r\n0\r\n\r\n";
    n = http_decode_chunked(in5, strlen(in5), out, sizeof(out));
    EXPECT_EQ_INT("chunked: bad hex", -1, n);

    /* Empty chunked body (just terminator) */
    const char *in6 = "0\r\n\r\n";
    n = http_decode_chunked(in6, strlen(in6), out, sizeof(out));
    EXPECT_EQ_INT("chunked: empty rc", 0, n);

    /* Output overflow */
    char tiny[4];
    const char *in7 = "a\r\n0123456789\r\n0\r\n\r\n";
    n = http_decode_chunked(in7, strlen(in7), tiny, sizeof(tiny));
    EXPECT_EQ_INT("chunked: overflow", -1, n);
}

static void test_headers_is_chunked(void)
{
    const char *h1 = "Content-Type: application/json\r\nTransfer-Encoding: chunked";
    EXPECT_EQ_INT("chunked hdr: yes",
                  1,
                  http_headers_is_chunked(h1, strlen(h1)));

    const char *h2 = "Transfer-Encoding: CHUNKED\r\nX-Other: v";
    EXPECT_EQ_INT("chunked hdr: uppercase",
                  1,
                  http_headers_is_chunked(h2, strlen(h2)));

    const char *h3 = "Content-Type: text/html\r\nContent-Length: 42";
    EXPECT_EQ_INT("chunked hdr: no",
                  0,
                  http_headers_is_chunked(h3, strlen(h3)));

    EXPECT_EQ_INT("chunked hdr: empty", 0, http_headers_is_chunked("", 0));
}

/* Run the same framing/verdict pipeline Postman uses on a raw response. */
static HttpVerdict assess(const char *raw, int is_head, HttpEnd end,
                          size_t *used_out)
{
    const char *status, *headers, *body;
    size_t status_len, headers_len, body_len, used = 0;
    size_t off = http_final_response_offset(raw, strlen(raw));
    HttpBodyState framing;

    if (http_split_response(raw + off, strlen(raw) - off,
                            &status, &status_len, &headers, &headers_len,
                            &body, &body_len) != 0)
        return kHttpVerdict_Malformed;
    framing = http_check_body_framing(status, status_len, headers, headers_len,
                                      body, body_len, is_head, &used);
    if (used_out) *used_out = used;
    return http_response_verdict(framing, end);
}

static void test_chunked_truncation(void)
{
    char out[256];
    size_t written = 0, consumed = 0;

    /* Terminal chunk without the final CRLF: the transfer was cut. */
    const char *cut1 = "5\r\nHello\r\n0\r\n";
    EXPECT_EQ_INT("chunked: missing final CRLF is incomplete",
                  kHttpChunk_Incomplete,
                  http_decode_chunked_ex(cut1, strlen(cut1), out, sizeof(out),
                                         &written, &consumed));
    EXPECT_EQ_INT("chunked: incomplete keeps decoded prefix", 5, (int)written);
    EXPECT_EQ_INT("chunked: decode wrapper rejects missing final CRLF", -1,
                  http_decode_chunked(cut1, strlen(cut1), out, sizeof(out)));

    /* Cut in the middle of a chunk's data */
    const char *cut2 = "a\r\n01234";
    EXPECT_EQ_INT("chunked: partial chunk data is incomplete",
                  kHttpChunk_Incomplete,
                  http_decode_chunked_ex(cut2, strlen(cut2), out, sizeof(out),
                                         &written, NULL));
    EXPECT_EQ_INT("chunked: partial chunk bytes kept", 5, (int)written);

    /* Cut in the middle of a size line / right after the data */
    const char *cut3 = "5\r\nHello\r\n1";
    EXPECT_EQ_INT("chunked: size line cut is incomplete", kHttpChunk_Incomplete,
                  http_decode_chunked_ex(cut3, strlen(cut3), out, sizeof(out),
                                         &written, NULL));
    const char *cut4 = "5\r\nHello";
    EXPECT_EQ_INT("chunked: missing CRLF after data is incomplete",
                  kHttpChunk_Incomplete,
                  http_decode_chunked_ex(cut4, strlen(cut4), out, sizeof(out),
                                         &written, NULL));
    EXPECT_EQ_INT("chunked: empty input is incomplete", kHttpChunk_Incomplete,
                  http_decode_chunked_ex("", 0, out, sizeof(out), &written, NULL));

    /* Trailers must be terminated too */
    const char *tr1 = "3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n";
    EXPECT_EQ_INT("chunked: trailers then blank line is done", kHttpChunk_Done,
                  http_decode_chunked_ex(tr1, strlen(tr1), out, sizeof(out),
                                         &written, &consumed));
    EXPECT_EQ_INT("chunked: consumed whole message", (int)strlen(tr1),
                  (int)consumed);
    const char *tr2 = "3\r\nabc\r\n0\r\nX-Sum: 1\r\n";
    EXPECT_EQ_INT("chunked: unterminated trailers are incomplete",
                  kHttpChunk_Incomplete,
                  http_decode_chunked_ex(tr2, strlen(tr2), out, sizeof(out),
                                         &written, NULL));

    /* Malformed is distinct from truncated */
    const char *bad1 = "5\r\nHelloXX0\r\n\r\n";
    EXPECT_EQ_INT("chunked: junk after data is malformed", kHttpChunk_Malformed,
                  http_decode_chunked_ex(bad1, strlen(bad1), out, sizeof(out),
                                         &written, NULL));
    const char *bad2 = "ffffffffffffffffff\r\n";
    EXPECT_EQ_INT("chunked: length overflow is malformed", kHttpChunk_Malformed,
                  http_decode_chunked_ex(bad2, strlen(bad2), out, sizeof(out),
                                         &written, NULL));
    char tiny[2];
    const char *big = "5\r\nHello\r\n0\r\n\r\n";
    EXPECT_EQ_INT("chunked: output overflow reported", kHttpChunk_Overflow,
                  http_decode_chunked_ex(big, strlen(big), tiny, sizeof(tiny),
                                         &written, NULL));

    /* Framing-only walk (out == NULL) */
    EXPECT_EQ_INT("chunked: NULL out walks framing", kHttpChunk_Done,
                  http_decode_chunked_ex(big, strlen(big), NULL, 0,
                                         &written, &consumed));

    /* In-place decoding still works */
    char inplace[] = "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    int n = http_decode_chunked(inplace, strlen(inplace), inplace,
                                sizeof(inplace));
    EXPECT_EQ_INT("chunked: in-place rc", 11, n);
    if (n == 11) EXPECT_EQ_MEM("chunked: in-place data", "Hello World", inplace, 11);

    /* Only a bare "chunked" token selects chunked framing */
    const char *te1 = "Transfer-Encoding: chunkedx";
    EXPECT_EQ_INT("chunked hdr: token must match exactly", 0,
                  http_headers_is_chunked(te1, strlen(te1)));
    const char *te2 = "Transfer-Encoding: chunked  ";
    EXPECT_EQ_INT("chunked hdr: trailing blanks ok", 1,
                  http_headers_is_chunked(te2, strlen(te2)));
}

static void test_content_length_framing(void)
{
    size_t used = 0;

    const char *full =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    EXPECT_EQ_INT("cl: complete body, authenticated close",
                  kHttpVerdict_Complete,
                  assess(full, 0, kHttpEnd_CloseNotify, &used));
    EXPECT_EQ_INT("cl: complete body, FIN without close_notify still complete",
                  kHttpVerdict_Complete,
                  assess(full, 0, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("cl: used = declared length", 5, (int)used);

    const char *cut =
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nHello";
    EXPECT_EQ_INT("cl: short body is incomplete (FIN)", kHttpVerdict_Incomplete,
                  assess(cut, 0, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("cl: short body is incomplete even after close_notify",
                  kHttpVerdict_Incomplete,
                  assess(cut, 0, kHttpEnd_CloseNotify, &used));
    EXPECT_EQ_INT("cl: incomplete keeps what arrived", 5, (int)used);

    const char *extra =
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef";
    EXPECT_EQ_INT("cl: surplus bytes beyond length", kHttpVerdict_Complete,
                  assess(extra, 0, kHttpEnd_CloseNotify, &used));
    EXPECT_EQ_INT("cl: surplus bytes are not part of the message", 3, (int)used);

    const char *zero = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    EXPECT_EQ_INT("cl: zero length", kHttpVerdict_Complete,
                  assess(zero, 0, kHttpEnd_Truncated, &used));

    const char *dup_ok =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nhi";
    EXPECT_EQ_INT("cl: repeated identical values", kHttpVerdict_Complete,
                  assess(dup_ok, 0, kHttpEnd_CloseNotify, &used));
    const char *dup_bad =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nhi";
    EXPECT_EQ_INT("cl: conflicting values are malformed", kHttpVerdict_Malformed,
                  assess(dup_bad, 0, kHttpEnd_CloseNotify, &used));
    const char *neg =
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nhi";
    EXPECT_EQ_INT("cl: negative is malformed", kHttpVerdict_Malformed,
                  assess(neg, 0, kHttpEnd_CloseNotify, &used));
    const char *junk =
        "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nhi";
    EXPECT_EQ_INT("cl: trailing junk is malformed", kHttpVerdict_Malformed,
                  assess(junk, 0, kHttpEnd_CloseNotify, &used));
    const char *huge =
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\nhi";
    EXPECT_EQ_INT("cl: overflowing value is malformed", kHttpVerdict_Malformed,
                  assess(huge, 0, kHttpEnd_CloseNotify, &used));
}

static void test_eof_delimited_and_bodyless(void)
{
    size_t used = 0;

    const char *eof = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed";
    EXPECT_EQ_INT("eof body: close_notify proves completeness",
                  kHttpVerdict_Complete,
                  assess(eof, 0, kHttpEnd_CloseNotify, &used));
    EXPECT_EQ_INT("eof body: FIN without close_notify is unverified",
                  kHttpVerdict_Unverified,
                  assess(eof, 0, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("eof body: everything received belongs to the body", 8,
                  (int)used);

    const char *gz = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx";
    EXPECT_EQ_INT("eof body: non-chunked coding is close-delimited",
                  kHttpVerdict_Unverified,
                  assess(gz, 0, kHttpEnd_Truncated, &used));

    const char *nc = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    EXPECT_EQ_INT("204 never has a body", kHttpVerdict_Complete,
                  assess(nc, 0, kHttpEnd_Truncated, &used));
    const char *nm = "HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n";
    EXPECT_EQ_INT("304 ignores Content-Length", kHttpVerdict_Complete,
                  assess(nm, 0, kHttpEnd_Truncated, &used));
    const char *hd = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n";
    EXPECT_EQ_INT("HEAD ignores Content-Length", kHttpVerdict_Complete,
                  assess(hd, 1, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("GET with the same bytes is incomplete", kHttpVerdict_Incomplete,
                  assess(hd, 0, kHttpEnd_Truncated, &used));

    const char *both =
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n"
        "\r\n2\r\nhi\r\n0\r\n\r\n";
    EXPECT_EQ_INT("Transfer-Encoding wins over Content-Length",
                  kHttpVerdict_Complete,
                  assess(both, 0, kHttpEnd_Truncated, &used));
}

static void test_chunked_framing(void)
{
    size_t used = 0;
    const char *full =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nHello\r\n0\r\n\r\n";
    EXPECT_EQ_INT("chunked resp: complete", kHttpVerdict_Complete,
                  assess(full, 0, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("chunked resp: used covers framing", 15, (int)used);

    const char *cut =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nHello\r\n0\r\n";
    EXPECT_EQ_INT("chunked resp: cut before final CRLF is incomplete",
                  kHttpVerdict_Incomplete,
                  assess(cut, 0, kHttpEnd_Truncated, &used));
    EXPECT_EQ_INT("chunked resp: stays incomplete after close_notify",
                  kHttpVerdict_Incomplete,
                  assess(cut, 0, kHttpEnd_CloseNotify, &used));

    const char *prefix =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nHello\r\n";
    EXPECT_EQ_INT("chunked resp: valid prefix without terminal chunk",
                  kHttpVerdict_Incomplete,
                  assess(prefix, 0, kHttpEnd_Truncated, &used));

    const char *bad =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "zz\r\nHello\r\n0\r\n\r\n";
    EXPECT_EQ_INT("chunked resp: bad chunk is malformed, not raw fallback",
                  kHttpVerdict_Malformed,
                  assess(bad, 0, kHttpEnd_CloseNotify, &used));
}

static void test_interim_and_truncated_headers(void)
{
    size_t used = 0;
    const char *raw =
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    EXPECT_EQ_INT("interim: skipped to final response", 25,
                  (int)http_final_response_offset(raw, strlen(raw)));
    EXPECT_EQ_INT("interim: final response judged", kHttpVerdict_Complete,
                  assess(raw, 0, kHttpEnd_CloseNotify, &used));

    const char *only = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n";
    EXPECT_EQ_INT("interim: no final response yet is malformed",
                  kHttpVerdict_Malformed,
                  assess(only, 0, kHttpEnd_Truncated, &used));

    const char *sw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n";
    EXPECT_EQ_INT("interim: 101 is final", 0,
                  (int)http_final_response_offset(sw, strlen(sw)));

    const char *hdrs = "HTTP/1.1 200 OK\r\nContent-Le";
    EXPECT_EQ_INT("cut headers have no message", kHttpVerdict_Malformed,
                  assess(hdrs, 0, kHttpEnd_Truncated, &used));
}

int main(void)
{
    test_smoke();
    test_parse_url();
    test_build_request();
    test_split_response();
    test_decode_chunked();
    test_headers_is_chunked();
    test_chunked_truncation();
    test_content_length_framing();
    test_eof_delimited_and_bodyless();
    test_chunked_framing();
    test_interim_and_truncated_headers();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
