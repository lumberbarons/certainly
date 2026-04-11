#include "http.h"
#include <string.h>

int http_parse_url(const char *url, size_t url_len,
                   char *host_out, size_t host_cap,
                   uint16_t *port_out,
                   char *path_out, size_t path_cap)
{
    (void)url; (void)url_len; (void)host_out; (void)host_cap;
    (void)port_out; (void)path_out; (void)path_cap;
    return -1;  /* filled in by Task 3 */
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
