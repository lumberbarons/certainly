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
 *   - malformed chunk length (non-hex before CRLF) or chunk framing
 *   - output overflow
 *   - an incomplete body: the zero-length chunk and the blank line that
 *     ends the trailer section must both be present
 *
 * Safe to pass out == in for in-place decoding (the output is always
 * shorter than the input, and we walk both cursors forward). */
int http_decode_chunked(const char *in, size_t in_len,
                        char *out, size_t out_cap);

typedef enum {
    kHttpChunk_Done,        /* terminal chunk and trailer terminator seen */
    kHttpChunk_Incomplete,  /* input ended mid-body: a truncated transfer */
    kHttpChunk_Malformed,   /* bytes that cannot be valid chunked framing */
    kHttpChunk_Overflow     /* decoded body does not fit in out_cap */
} HttpChunkState;

/* Like http_decode_chunked but tells the failure modes apart. *written_out
 * receives the decoded bytes so far (for Incomplete this includes a chunk
 * that only partly arrived) and *consumed_out the input bytes parsed; either
 * may be NULL. Passing out == NULL only checks the framing. */
HttpChunkState http_decode_chunked_ex(const char *in, size_t in_len,
                                      char *out, size_t out_cap,
                                      size_t *written_out,
                                      size_t *consumed_out);

/* Offset of the final response in raw, past any complete 1xx interim
 * responses (100 Continue, 103 Early Hints). 101 is final. */
size_t http_final_response_offset(const char *raw, size_t raw_len);

typedef enum {
    kHttpBody_Complete,   /* message fully received per its own framing */
    kHttpBody_Incomplete, /* Content-Length / terminal chunk not reached */
    kHttpBody_UntilClose, /* no length info: the connection close ends it */
    kHttpBody_Malformed   /* bad or ambiguous framing */
} HttpBodyState;

/* Decide whether the bytes after the header block form a complete
 * message. status_line/headers/body are the regions from
 * http_split_response. is_head is non-zero when the request was HEAD.
 * *body_used_out (may be NULL) is how many body bytes belong to the
 * message: Content-Length bytes, the raw chunked bytes through the trailer
 * terminator, or everything received for Incomplete and UntilClose. */
HttpBodyState http_check_body_framing(const char *status_line, size_t status_len,
                                      const char *headers, size_t headers_len,
                                      const char *body, size_t body_len,
                                      int is_head, size_t *body_used_out);

typedef enum {
    kHttpEnd_CloseNotify,  /* TLS peer sent an authenticated close_notify */
    kHttpEnd_Truncated     /* transport ended without one (kMacTLS_ErrTruncated) */
} HttpEnd;

typedef enum {
    kHttpVerdict_Complete,    /* safe to present as a finished response */
    kHttpVerdict_Incomplete,  /* declared length / terminal chunk missing */
    kHttpVerdict_Unverified,  /* body ran to a close that was not authenticated */
    kHttpVerdict_Malformed
} HttpVerdict;

/* Combine message framing with how the TLS stream ended. A message that
 * is complete by its own framing is trustworthy whichever way the stream
 * ended; a body delimited only by the close needs the close_notify. */
HttpVerdict http_response_verdict(HttpBodyState framing, HttpEnd end);

#ifdef __cplusplus
}
#endif

#endif
