#ifndef POSTMAN_HTTP_H
#define POSTMAN_HTTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int http_parse_url(const char *url,    size_t url_len,
                   char       *host_out, size_t host_cap,
                   uint16_t   *port_out,
                   char       *path_out, size_t path_cap);

int http_build_request(const char *method,
                       const char *host,
                       const char *path,
                       const char *user_headers, size_t user_headers_len,
                       const char *body,         size_t body_len,
                       char       *out_buf,      size_t out_cap);

int http_split_response(const char *raw, size_t raw_len,
                        const char **status_line_out, size_t *status_len_out,
                        const char **headers_out,     size_t *headers_len_out,
                        const char **body_out,        size_t *body_len_out);

#ifdef __cplusplus
}
#endif

#endif
