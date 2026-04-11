#include "http.h"
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

int http_build_request(const char *method, const char *host,
                       const char *path,
                       const char *user_headers, size_t user_headers_len,
                       const char *body, size_t body_len,
                       char *out_buf, size_t out_cap)
{
    (void)method; (void)host; (void)path;
    (void)user_headers; (void)user_headers_len;
    (void)body; (void)body_len; (void)out_buf; (void)out_cap;
    return -1;  /* filled in by Task 4 */
}

int http_split_response(const char *raw, size_t raw_len,
                        const char **status_line_out, size_t *status_len_out,
                        const char **headers_out,     size_t *headers_len_out,
                        const char **body_out,        size_t *body_len_out)
{
    (void)raw; (void)raw_len;
    (void)status_line_out; (void)status_len_out;
    (void)headers_out;     (void)headers_len_out;
    (void)body_out;        (void)body_len_out;
    return -1;  /* filled in by Task 5 */
}
