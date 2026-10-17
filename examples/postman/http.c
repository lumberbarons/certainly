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

            /* Compare the value case-insensitively to "chunked". Anything
             * after the token (other than trailing blanks) is a different
             * coding, which would make the body framing unknowable. */
            if ((size_t)(line_end - v) >= 7) {
                const char *want = "chunked";
                int match = 1;
                for (int i = 0; i < 7; i++) {
                    char a = v[i];
                    char b = want[i];
                    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                    if (a != b) { match = 0; break; }
                }
                for (const char *t = v + 7; match && t < line_end; t++) {
                    if (*t != ' ' && *t != '\t') match = 0;
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
 * Consume one line terminator (CRLF, or a bare LF from sloppy servers).
 * Returns 1 if consumed, 0 if the input ends before the terminator is
 * complete (a lone trailing CR counts), -1 if the bytes there are not a
 * terminator.
 */
static int eat_eol(const char **p, const char *e)
{
    if (*p >= e) return 0;
    if (**p == '\n') { (*p)++; return 1; }
    if (**p != '\r') return -1;
    if (*p + 1 >= e) return 0;
    if ((*p)[1] != '\n') return -1;
    *p += 2;
    return 1;
}

/*
 * Walk a chunked body (out == NULL: framing check only, nothing copied).
 * A body only counts as Done once the zero-length
 * chunk AND the blank line ending the trailer section were seen; running
 * out of input anywhere before that is Incomplete, which is how a
 * truncated transfer differs from a malformed one. On Incomplete,
 * *written still holds the decoded bytes that did arrive, including a
 * partially received chunk.
 */
HttpChunkState http_decode_chunked_ex(const char *in, size_t in_len,
                                      char *out, size_t out_cap,
                                      size_t *written_out,
                                      size_t *consumed_out)
{
    const char *p = in;
    const char *e = in + in_len;
    size_t written = 0;
    HttpChunkState st = kHttpChunk_Incomplete;

    for (;;) {
        size_t chunk_len = 0;
        int any_digits = 0;
        int r;

        while (p < e) {
            int d = hex_digit(*p);
            if (d < 0) break;
            if (chunk_len > ((size_t)-1 >> 4)) { st = kHttpChunk_Malformed; goto done; }
            chunk_len = (chunk_len << 4) | (size_t)d;
            any_digits = 1;
            p++;
        }
        if (p >= e) break;                       /* length line unfinished */
        if (!any_digits) { st = kHttpChunk_Malformed; goto done; }

        /* Skip optional chunk extension ("; foo=bar"). */
        while (p < e && *p != '\r' && *p != '\n') p++;
        r = eat_eol(&p, e);
        if (r < 0) { st = kHttpChunk_Malformed; goto done; }
        if (r == 0) break;

        if (chunk_len == 0) {
            /* Trailer section: header lines, then an empty line. */
            for (;;) {
                const char *line = p;
                int blank;
                while (p < e && *p != '\r' && *p != '\n') p++;
                blank = (p == line);
                r = eat_eol(&p, e);
                if (r < 0) { st = kHttpChunk_Malformed; goto done; }
                if (r == 0) goto done;           /* trailers cut short */
                if (blank) { st = kHttpChunk_Done; goto done; }
            }
        }

        {
            size_t avail = (size_t)(e - p);
            size_t take = avail < chunk_len ? avail : chunk_len;

            if (out != NULL) {
                if (written + take > out_cap) { st = kHttpChunk_Overflow; goto done; }
                /* memmove in case out == in (in-place). */
                memmove(out + written, p, take);
            }
            written += take;
            p += take;
            if (take < chunk_len) break;         /* chunk data cut short */
        }

        r = eat_eol(&p, e);
        if (r < 0) { st = kHttpChunk_Malformed; goto done; }
        if (r == 0) break;
    }

done:
    if (written_out) *written_out = written;
    if (consumed_out) *consumed_out = (size_t)(p - in);
    return st;
}

/*
 * Decode an HTTP/1.1 chunked body into `out`. Returns the number of
 * decoded bytes, or -1 if the body is malformed, overflows `out`, or is
 * not complete (see http_decode_chunked_ex to tell those apart). Safe to
 * pass out == in for in-place decoding (output is always shorter).
 */
int http_decode_chunked(const char *in, size_t in_len,
                        char *out, size_t out_cap)
{
    size_t written;
    if (http_decode_chunked_ex(in, in_len, out, out_cap,
                               &written, NULL) != kHttpChunk_Done)
        return -1;
    return (int)written;
}

/* Parse the three-digit status code of an HTTP status line, or -1. */
static int status_code_of(const char *status_line, size_t status_len)
{
    size_t i = 0;
    int code = 0;
    while (i < status_len && status_line[i] != ' ') i++;
    if (i >= status_len) return -1;
    i++;
    if (i + 3 > status_len) return -1;
    for (int k = 0; k < 3; k++) {
        char c = status_line[i + (size_t)k];
        if (c < '0' || c > '9') return -1;
        code = code * 10 + (c - '0');
    }
    if (i + 3 < status_len && status_line[i + 3] != ' ') return -1;
    return code;
}

size_t http_final_response_offset(const char *raw, size_t raw_len)
{
    size_t off = 0;

    for (;;) {
        const char *status, *headers, *body;
        size_t status_len, headers_len, body_len;
        int code;

        if (http_split_response(raw + off, raw_len - off,
                                &status, &status_len,
                                &headers, &headers_len,
                                &body, &body_len) != 0)
            return off;
        code = status_code_of(status, status_len);
        if (code < 100 || code > 199 || code == 101) return off;
        off = (size_t)(body - raw);
    }
}

/*
 * Parse the Content-Length headers. Returns 1 and sets *len when exactly
 * one distinct valid value is present, 0 if the header is absent, and -1
 * if it is malformed or repeated with conflicting values (the message
 * length is then ambiguous).
 */
static int content_length_of(const char *headers, size_t headers_len,
                             size_t *len_out)
{
    const char *p = headers;
    const char *e = headers + headers_len;
    int found = 0;
    size_t value = 0;

    while (p < e) {
        const char *line_end = p;
        while (line_end < e && *line_end != '\r' && *line_end != '\n')
            line_end++;

        if (header_line_is(p, (size_t)(line_end - p), "Content-Length")) {
            const char *v = p + 15;
            size_t n = 0;
            int digits = 0;

            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
            while (v < line_end && *v >= '0' && *v <= '9') {
                if (n > ((size_t)-1 - 9) / 10) return -1;
                n = n * 10 + (size_t)(*v - '0');
                digits = 1;
                v++;
            }
            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
            if (!digits || v != line_end) return -1;
            if (found && n != value) return -1;
            found = 1;
            value = n;
        }

        if (line_end < e && *line_end == '\r') line_end++;
        if (line_end < e && *line_end == '\n') line_end++;
        p = line_end;
    }

    if (found) *len_out = value;
    return found;
}

static int has_header(const char *headers, size_t headers_len,
                      const char *name)
{
    const char *p = headers;
    const char *e = headers + headers_len;

    while (p < e) {
        const char *line_end = p;
        while (line_end < e && *line_end != '\r' && *line_end != '\n')
            line_end++;
        if (header_line_is(p, (size_t)(line_end - p), name)) return 1;
        if (line_end < e && *line_end == '\r') line_end++;
        if (line_end < e && *line_end == '\n') line_end++;
        p = line_end;
    }
    return 0;
}

HttpBodyState http_check_body_framing(const char *status_line, size_t status_len,
                                      const char *headers, size_t headers_len,
                                      const char *body, size_t body_len,
                                      int is_head, size_t *body_used_out)
{
    size_t used = 0;
    HttpBodyState st;
    int code = status_code_of(status_line, status_len);
    size_t clen = 0;
    int cl;

    if (code < 0) {
        st = kHttpBody_Malformed;
    } else if (is_head || code < 200 || code == 204 || code == 304) {
        /* These messages never carry a body, whatever the headers say. */
        st = kHttpBody_Complete;
    } else if (has_header(headers, headers_len, "Transfer-Encoding")) {
        /* Transfer-Encoding overrides Content-Length (RFC 9112 6.3). A
         * coding list that does not end in bare "chunked" is delimited
         * only by the connection closing. */
        if (http_headers_is_chunked(headers, headers_len)) {
            /* A NULL output walks the framing without copying. */
            HttpChunkState cs = http_decode_chunked_ex(
                body, body_len, NULL, 0, NULL, &used);
            if (cs == kHttpChunk_Done) {
                st = kHttpBody_Complete;
            } else if (cs == kHttpChunk_Incomplete) {
                st = kHttpBody_Incomplete;
                used = body_len;
            } else {
                st = kHttpBody_Malformed;
                used = 0;
            }
        } else {
            st = kHttpBody_UntilClose;
            used = body_len;
        }
    } else if ((cl = content_length_of(headers, headers_len, &clen)) < 0) {
        st = kHttpBody_Malformed;
    } else if (cl == 1) {
        if (body_len >= clen) { st = kHttpBody_Complete; used = clen; }
        else { st = kHttpBody_Incomplete; used = body_len; }
    } else {
        st = kHttpBody_UntilClose;
        used = body_len;
    }

    if (body_used_out) *body_used_out = used;
    return st;
}

HttpVerdict http_response_verdict(HttpBodyState framing, HttpEnd end)
{
    switch (framing) {
    case kHttpBody_Complete:   return kHttpVerdict_Complete;
    case kHttpBody_Incomplete: return kHttpVerdict_Incomplete;
    case kHttpBody_UntilClose:
        /* The close itself delimits the body, so only an authenticated
         * close_notify proves nothing was cut off. */
        return end == kHttpEnd_CloseNotify ? kHttpVerdict_Complete
                                           : kHttpVerdict_Unverified;
    default:                   return kHttpVerdict_Malformed;
    }
}
