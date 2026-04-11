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

/* Returns 1 if the headers region (as returned by http_split_response)
 * contains a Transfer-Encoding: chunked header (case-insensitive name
 * and value match), 0 otherwise.
 *
 * The headers buffer is the raw "Name: Value\r\n..." block between the
 * status line and the blank-line terminator. */
int http_headers_is_chunked(const char *headers, size_t headers_len);

/* Decode an HTTP/1.1 chunked body. in/in_len is the raw body as
 * returned by http_split_response; out/out_cap is a caller-supplied
 * output buffer that receives the decoded bytes.
 *
 * Returns the number of decoded bytes on success, or -1 on:
 *   - malformed chunk length (non-hex before CRLF)
 *   - chunk extends past in_len
 *   - output overflow
 *   - missing terminator (0-length chunk)
 *
 * Safe to pass out == in for in-place decoding (the output is always
 * shorter than the input, and we walk both cursors forward). */
int http_decode_chunked(const char *in, size_t in_len,
                        char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
