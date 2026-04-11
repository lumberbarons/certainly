#include "http.h"
#include <stdio.h>
#include <string.h>

/* Copy src_len bytes from src into dst, NUL-terminated.
 * Returns 0 on success, -1 if src doesn't fit in dst_cap (including the
 * terminator). */
static int copy_bounded(char *dst, size_t dst_cap,
                        const char *src, size_t src_len)
{
    if (src_len + 1 > dst_cap) return -1;
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return 0;
}

/* Parse scheme://host[:port]/path[?query][#fragment] into components.
 *
 * Only http:// and https:// schemes are accepted. Default port is
 * 443 for https, 80 for http. Fragments are stripped. An empty or
 * missing path is normalized to "/". Both host_out and path_out are
 * written NUL-terminated on success.
 *
 * Returns 0 on success, -1 on any failure (malformed URL, empty
 * host, port out of range, or output-buffer overflow). On failure
 * the contents of host_out, path_out, and *port_out are
 * unspecified — callers must check the return code before using
 * any output.
 */
int http_parse_url(const char *url, size_t url_len,
                   char *host_out, size_t host_cap,
                   uint16_t *port_out,
                   char *path_out, size_t path_cap)
{
    const char *end = url + url_len;
    const char *p   = url;
    int is_https;

    /* Scheme */
    if (url_len >= 8 && memcmp(p, "https://", 8) == 0) {
        is_https = 1;
        p += 8;
    } else if (url_len >= 7 && memcmp(p, "http://", 7) == 0) {
        is_https = 0;
        p += 7;
    } else {
        return -1;
    }

    /* Authority: host[:port]. Ends at '/', '?', '#', or end-of-string. */
    const char *host_start = p;
    const char *host_end   = p;
    while (host_end < end && *host_end != ':' && *host_end != '/'
           && *host_end != '?' && *host_end != '#') {
        host_end++;
    }
    if (host_end == host_start) return -1;  /* empty host */

    if (copy_bounded(host_out, host_cap, host_start,
                     (size_t)(host_end - host_start)) != 0) {
        return -1;
    }

    /* Port */
    uint16_t port = is_https ? 443 : 80;
    p = host_end;
    if (p < end && *p == ':') {
        p++;
        unsigned long n = 0;
        const char *digits_start = p;
        while (p < end && *p >= '0' && *p <= '9') {
            n = n * 10 + (unsigned long)(*p - '0');
            if (n > 65535) return -1;
            p++;
        }
        if (p == digits_start) return -1;  /* ':' with no digits */
        port = (uint16_t)n;
    }
    *port_out = port;

    /* Path (everything from '/' onward, stripping fragment) */
    const char *path_start = p;
    const char *path_end   = end;
    /* Strip fragment */
    for (const char *q = path_start; q < path_end; q++) {
        if (*q == '#') { path_end = q; break; }
    }

    if (path_start == path_end || *path_start != '/') {
        /* Empty path → "/" */
        return copy_bounded(path_out, path_cap, "/", 1);
    }

    return copy_bounded(path_out, path_cap, path_start,
                        (size_t)(path_end - path_start));
}

/* Case-insensitive prefix compare: does a header line start with "prefix:"? */
static int header_line_is(const char *line, size_t line_len,
                          const char *prefix)
{
    size_t plen = strlen(prefix);
    if (line_len < plen + 1) return 0;
    for (size_t i = 0; i < plen; i++) {
        char a = line[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return line[plen] == ':';
}

/* Append a NUL-terminated string to a write cursor, bounds-checked.
 * Returns 0 on success, -1 if it won't fit. */
static int append_str(char **cursor, char *end, const char *s)
{
    size_t n = strlen(s);
    if ((size_t)(end - *cursor) < n) return -1;
    memcpy(*cursor, s, n);
    *cursor += n;
    return 0;
}

/* Append raw bytes. Same semantics. */
static int append_bytes(char **cursor, char *end, const char *s, size_t n)
{
    if ((size_t)(end - *cursor) < n) return -1;
    memcpy(*cursor, s, n);
    *cursor += n;
    return 0;
}

static int method_has_body(const char *method)
{
    return strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0;
}

/*
 * Build a complete HTTP/1.1 request into out_buf.
 *
 * Always emits Host: <host> first (library-controlled, not user-
 * overridable to prevent TLS SNI mismatches). Always emits
 * Connection: close. Emits User-Agent: Certainly/0.1 unless the
 * user supplied their own. Emits Content-Length when method is
 * POST or PUT with a non-NULL body.
 *
 * User-supplied headers are parsed from a flat block separated by
 * '\n' or '\r\n'. Blank lines are skipped. Duplicates of the library-
 * controlled headers (Host, Connection, Content-Length) are
 * stripped. All user headers are re-emitted with CRLF.
 *
 * For GET and DELETE methods, any supplied body is silently stripped.
 *
 * Returns the number of bytes written, or -1 on output overflow.
 */
int http_build_request(const char *method, const char *host,
                       const char *path,
                       const char *user_headers, size_t user_headers_len,
                       const char *body, size_t body_len,
                       char *out_buf, size_t out_cap)
{
    char *cur = out_buf;
    char *end = out_buf + out_cap;

    /* Request line */
    if (append_str(&cur, end, method) != 0) return -1;
    if (append_str(&cur, end, " ")    != 0) return -1;
    if (append_str(&cur, end, path)   != 0) return -1;
    if (append_str(&cur, end, " HTTP/1.1\r\n") != 0) return -1;

    /* Host is always ours */
    if (append_str(&cur, end, "Host: ") != 0) return -1;
    if (append_str(&cur, end, host)     != 0) return -1;
    if (append_str(&cur, end, "\r\n")   != 0) return -1;

    /* Scan user headers for User-Agent override. */
    int user_has_ua = 0;
    if (user_headers && user_headers_len > 0) {
        const char *p = user_headers;
        const char *e = user_headers + user_headers_len;
        while (p < e) {
            const char *line_end = p;
            while (line_end < e && *line_end != '\n' && *line_end != '\r')
                line_end++;
            if (header_line_is(p, (size_t)(line_end - p), "User-Agent"))
                user_has_ua = 1;
            /* advance past CR, LF, or CRLF */
            if (line_end < e && *line_end == '\r') line_end++;
            if (line_end < e && *line_end == '\n') line_end++;
            p = line_end;
        }
    }

    if (!user_has_ua) {
        if (append_str(&cur, end, "User-Agent: Certainly/0.1\r\n") != 0)
            return -1;
    }

    /* Always close. */
    if (append_str(&cur, end, "Connection: close\r\n") != 0) return -1;

    /* User-supplied headers, with Host:, Connection:, and Content-Length:
     * stripped. LF-only lines get CRLF. Emitted before Content-Length so
     * Content-Type (and friends) appear before the length line. */
    if (user_headers && user_headers_len > 0) {
        const char *p = user_headers;
        const char *e = user_headers + user_headers_len;
        while (p < e) {
            const char *line_end = p;
            while (line_end < e && *line_end != '\n' && *line_end != '\r')
                line_end++;
            size_t line_len = (size_t)(line_end - p);

            /* Skip blank lines */
            if (line_len > 0) {
                int drop = header_line_is(p, line_len, "Host")
                        || header_line_is(p, line_len, "Connection")
                        || header_line_is(p, line_len, "Content-Length");
                if (!drop) {
                    if (append_bytes(&cur, end, p, line_len) != 0) return -1;
                    if (append_str(&cur, end, "\r\n") != 0) return -1;
                }
            }
            if (line_end < e && *line_end == '\r') line_end++;
            if (line_end < e && *line_end == '\n') line_end++;
            p = line_end;
        }
    }

    /* Content-Length (only for methods that carry bodies) */
    if (method_has_body(method) && body && body_len > 0) {
        char cl[48];
        int cn = snprintf(cl, sizeof(cl), "Content-Length: %lu\r\n",
                          (unsigned long)body_len);
        if (cn < 0 || (size_t)cn >= sizeof(cl)) return -1;
        if (append_str(&cur, end, cl) != 0) return -1;
    }

    /* Blank line terminator */
    if (append_str(&cur, end, "\r\n") != 0) return -1;

    /* Body (POST/PUT only; GET/DELETE strip silently) */
    if (method_has_body(method) && body && body_len > 0) {
        if (append_bytes(&cur, end, body, body_len) != 0) return -1;
    }

    /* NUL-terminate for callers that use strcmp / strlen */
    if (cur >= end) return -1;
    *cur = '\0';

    return (int)(cur - out_buf);
}

/*
 * Split a raw HTTP/1.1 response into status line, headers, and body
 * regions. All outputs are pointers into the caller's `raw` buffer;
 * no copies are made, and the lifetime of the outputs is tied to
 * `raw`.
 *
 * status_line   = bytes up to the first \r\n (not including the CRLF)
 * headers       = bytes between the status CRLF and the blank-line
 *                 terminator (not including either CRLF)
 * body          = bytes after the \r\n\r\n terminator, to end of input
 *
 * Returns 0 on success, -1 on any failure (NULL input, too short, no
 * status-line terminator, or no blank-line terminator). On failure the
 * output pointers/lengths are unspecified — callers must check the
 * return code first.
 */
int http_split_response(const char *raw, size_t raw_len,
                        const char **status_line_out, size_t *status_len_out,
                        const char **headers_out,     size_t *headers_len_out,
                        const char **body_out,        size_t *body_len_out)
{
    if (raw == NULL || raw_len < 4) return -1;

    /* Find end of status line: first "\r\n". */
    size_t i = 0;
    while (i + 1 < raw_len && !(raw[i] == '\r' && raw[i + 1] == '\n'))
        i++;
    if (i + 1 >= raw_len) return -1;  /* no CRLF */

    const char *status      = raw;
    size_t      status_len  = i;

    /* Find end of headers: first "\r\n\r\n" at or after position i. */
    size_t j = i;
    while (j + 3 < raw_len &&
           !(raw[j]   == '\r' && raw[j + 1] == '\n' &&
             raw[j+2] == '\r' && raw[j + 3] == '\n'))
        j++;
    if (j + 3 >= raw_len) return -1;  /* no blank-line terminator */

    /* Headers region is the bytes between the status-line CRLF
     * and the blank-line CRLF, NOT including either terminator. */
    const char *headers     = raw + (i + 2);        /* skip status CRLF */
    size_t      headers_len = (j > (i + 2)) ? (j - (i + 2)) : 0;

    const char *body        = raw + (j + 4);        /* skip "\r\n\r\n" */
    size_t      body_len    = raw_len - (j + 4);

    *status_line_out = status;
    *status_len_out  = status_len;
    *headers_out     = headers;
    *headers_len_out = headers_len;
    *body_out        = body;
    *body_len_out    = body_len;
    return 0;
}

/*
 * Returns non-zero if the caller-supplied headers block contains a
 * Transfer-Encoding header whose value (case-insensitive) is exactly
 * "chunked". Chunk extensions and compound Transfer-Encoding chains
 * (e.g. "gzip, chunked") are NOT supported — we only recognize the
 * bare case for simplicity.
 */
int http_headers_is_chunked(const char *headers, size_t headers_len)
{
    if (!headers || headers_len == 0) return 0;

    const char *p = headers;
    const char *e = headers + headers_len;
    while (p < e) {
        /* Find end of line */
        const char *line_end = p;
        while (line_end < e && *line_end != '\r' && *line_end != '\n')
            line_end++;
        size_t line_len = (size_t)(line_end - p);

        if (header_line_is(p, line_len, "Transfer-Encoding")) {
            /* Skip "Transfer-Encoding:" prefix (18 chars), then any
             * leading whitespace. */
            const char *v = p + 18;
            while (v < line_end && (*v == ' ' || *v == '\t')) v++;

            /* Compare the value case-insensitively to "chunked". */
            if ((size_t)(line_end - v) >= 7) {
                const char *want = "chunked";
                int match = 1;
                for (int i = 0; i < 7; i++) {
                    char a = v[i];
                    char b = want[i];
                    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                    if (a != b) { match = 0; break; }
                }
                if (match) return 1;
            }
        }

        /* Advance past CR, LF, or CRLF */
        if (line_end < e && *line_end == '\r') line_end++;
        if (line_end < e && *line_end == '\n') line_end++;
        p = line_end;
    }
    return 0;
}

/* Parse a hex digit. Returns -1 on non-hex. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Decode an HTTP/1.1 chunked body into `out`. Returns the number of
 * decoded bytes, or -1 on malformed input or output overflow. Safe
 * to pass out == in for in-place decoding (output is always shorter).
 */
int http_decode_chunked(const char *in, size_t in_len,
                        char *out, size_t out_cap)
{
    const char *p = in;
    const char *e = in + in_len;
    size_t written = 0;

    while (p < e) {
        /* Parse hex length. */
        size_t chunk_len = 0;
        int any_digits = 0;
        while (p < e) {
            int d = hex_digit(*p);
            if (d < 0) break;
            chunk_len = (chunk_len << 4) | (size_t)d;
            any_digits = 1;
            p++;
        }
        if (!any_digits) return -1;

        /* Skip optional chunk extension ("; foo=bar"). */
        while (p < e && *p != '\r' && *p != '\n') p++;

        /* Consume CR, LF, or CRLF after the length line. */
        if (p < e && *p == '\r') p++;
        if (p < e && *p == '\n') p++;
        else return -1;  /* malformed: expected LF after length */

        if (chunk_len == 0) {
            /* Terminator chunk. Optional trailers follow, then blank
             * line. We don't parse trailers — just return. */
            return (int)written;
        }

        /* Check we have enough input bytes for the chunk data. */
        if ((size_t)(e - p) < chunk_len) return -1;

        /* Copy into output, bounds-checked. */
        if (written + chunk_len > out_cap) return -1;

        /* memmove in case out == in (in-place). */
        memmove(out + written, p, chunk_len);
        written += chunk_len;
        p += chunk_len;

        /* Consume trailing CR, LF, or CRLF after chunk data. */
        if (p < e && *p == '\r') p++;
        if (p < e && *p == '\n') p++;
    }

    /* Reached end of input without seeing a terminator chunk. */
    return -1;
}
