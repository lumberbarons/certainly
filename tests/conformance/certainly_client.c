/*
 * certainly_client.c — bounded command-line TLS client for conformance runs
 *
 * Drives the production pump (src/certainly.c) from a native event loop
 * against a peer chosen by the caller. One process makes one attempt:
 * fresh library state, one connection, a hard deadline, then a single
 * JSON "result" line describing what happened. Exit status classifies the
 * outcome so a runner can tell a rejected certificate from a trust-anchor
 * file that would not load, a refused connection, a stalled peer or a
 * missing entropy source.
 *
 * Positive tests pass only on TLS 1.3 (a TLS 1.2 fallback is reported as
 * its own outcome). Negative tests are judged by the caller from the
 * outcome and the logged errors; this program does not decide that a
 * failure was the expected one.
 *
 * Build and run through tests/host/Makefile (make conformance-client).
 */

#define _POSIX_C_SOURCE 200809L

#include "certainly_internal.h"
#include "host_platform.h"
#include "trust_anchors.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* From bearssl/tools/errors.c. */
const char *find_error_name(int err, const char **comment);

/* ── Outcomes ── */

typedef enum {
    OUT_SUCCESS = 0,
    OUT_HANDSHAKE_ERROR = 10,   /* TLS failure that is not one of the below */
    OUT_CERTIFICATE_ERROR = 11, /* chain, name, validity or signature check */
    OUT_TIMEOUT = 12,           /* deadline passed with the peer silent */
    OUT_PEER_EOF = 13,          /* TCP FIN before the exchange completed */
    OUT_PEER_RESET = 14,        /* connection reset or other hard failure */
    OUT_TLS12_FALLBACK = 15,    /* connected, but not over TLS 1.3 */
    OUT_DATA_MISMATCH = 16,     /* application bytes differ from expected */
    OUT_CONNECT_ERROR = 17,     /* TCP never came up */
    OUT_PEER_ALERT = 18,        /* TLS alert/close before completion */
    OUT_USAGE = 20,
    OUT_ENTROPY_ERROR = 21,     /* no trusted seed; nothing was sent */
    OUT_SETUP_ERROR = 22,       /* fixtures or files unusable */
    OUT_MEMORY_ERROR = 23
} outcome;

static const char *outcome_name(outcome o)
{
    switch (o) {
    case OUT_SUCCESS:           return "success";
    case OUT_HANDSHAKE_ERROR:   return "handshake-error";
    case OUT_CERTIFICATE_ERROR: return "certificate-error";
    case OUT_TIMEOUT:           return "timeout";
    case OUT_PEER_EOF:          return "peer-eof";
    case OUT_PEER_RESET:        return "peer-reset";
    case OUT_TLS12_FALLBACK:    return "tls12-fallback";
    case OUT_DATA_MISMATCH:     return "data-mismatch";
    case OUT_CONNECT_ERROR:     return "connect-error";
    case OUT_PEER_ALERT:        return "peer-alert";
    case OUT_USAGE:             return "usage";
    case OUT_ENTROPY_ERROR:     return "entropy-error";
    case OUT_SETUP_ERROR:       return "setup-error";
    case OUT_MEMORY_ERROR:      return "memory-error";
    }
    return "unknown";
}

/* ── Options ── */

typedef enum { ENTROPY_OS, ENTROPY_NONE, ENTROPY_FAIL } entropy_mode;

typedef struct {
    const char   *attempt;
    const char   *connect_host;
    uint16_t      port;
    const char   *server_name;
    const char   *ca_file;
    int           data_mode;
    const char   *send_file;
    const char   *expect_file;
    int           until_close;
    const char   *out_file;
    const char   *log_file;
    int64_t       deadline_ms;
    int           have_validation_time;
    int64_t       validation_time;
    entropy_mode  entropy;
    host_transport_faults faults;
    int           allow_tls12;
    long          alloc_fail_after;
} options;

static void usage(void)
{
    fputs(
"usage: certainly_client --attempt ID --connect IP:PORT --server-name NAME\n"
"                        --ca FILE [options]\n"
"\n"
"  --mode handshake|data      handshake only (default) or exchange data\n"
"  --send FILE                data: bytes to write once connected\n"
"  --expect FILE              data: finish after exactly these bytes arrive\n"
"  --recv-until-close         data: read until the peer closes with an alert\n"
"  --out FILE                 data: store everything received\n"
"  --deadline-ms N            whole-attempt limit (default 15000)\n"
"  --validation-time UNIX     X.509 validation time (default: OS clock)\n"
"  --entropy os|none|fail     trusted entropy provider (default os)\n"
"  --read-chunk N             cap bytes per transport read\n"
"  --write-chunk N            cap bytes per transport write\n"
"  --wouldblock-every N       report no-data/no-room on every Nth call\n"
"  --alloc-fail-after N       fail Memory Manager allocations after N\n"
"  --allow-tls12              accept a TLS 1.2 fallback as success\n"
"  --log FILE                 JSON event log (default stdout)\n"
"\n"
"The destination must be an IP literal; --server-name is what SNI and\n"
"certificate checks use. Exit status is the outcome code in the result line.\n",
        stderr);
}

static int parse_ll(const char *s, int64_t *out)
{
    char *end;
    long long v;

    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0) return -1;
    *out = v;
    return 0;
}

static int parse_options(int argc, char **argv, options *o)
{
    int i;

    memset(o, 0, sizeof(*o));
    o->deadline_ms = 15000;
    o->alloc_fail_after = -1;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        int64_t n;

        if (strcmp(a, "--allow-tls12") == 0) { o->allow_tls12 = 1; continue; }
        if (strcmp(a, "--recv-until-close") == 0) { o->until_close = 1; continue; }
        if (v == NULL) {
            fprintf(stderr, "missing value for %s\n", a);
            return -1;
        }
        i++;
        if (strcmp(a, "--attempt") == 0) o->attempt = v;
        else if (strcmp(a, "--server-name") == 0) o->server_name = v;
        else if (strcmp(a, "--ca") == 0) o->ca_file = v;
        else if (strcmp(a, "--send") == 0) o->send_file = v;
        else if (strcmp(a, "--expect") == 0) o->expect_file = v;
        else if (strcmp(a, "--out") == 0) o->out_file = v;
        else if (strcmp(a, "--log") == 0) o->log_file = v;
        else if (strcmp(a, "--connect") == 0) {
            const char *colon = strrchr(v, ':');
            char *host;

            if (colon == NULL || parse_ll(colon + 1, &n) != 0 || n < 1 ||
                n > 65535) {
                fprintf(stderr, "bad --connect %s (want IP:PORT)\n", v);
                return -1;
            }
            host = (char *)malloc((size_t)(colon - v) + 1);
            memcpy(host, v, (size_t)(colon - v));
            host[colon - v] = '\0';
            o->connect_host = host;
            o->port = (uint16_t)n;
        } else if (strcmp(a, "--mode") == 0) {
            if (strcmp(v, "data") == 0) o->data_mode = 1;
            else if (strcmp(v, "handshake") == 0) o->data_mode = 0;
            else { fprintf(stderr, "bad --mode %s\n", v); return -1; }
        } else if (strcmp(a, "--entropy") == 0) {
            if (strcmp(v, "os") == 0) o->entropy = ENTROPY_OS;
            else if (strcmp(v, "none") == 0) o->entropy = ENTROPY_NONE;
            else if (strcmp(v, "fail") == 0) o->entropy = ENTROPY_FAIL;
            else { fprintf(stderr, "bad --entropy %s\n", v); return -1; }
        } else if (strcmp(a, "--deadline-ms") == 0 ||
                   strcmp(a, "--read-chunk") == 0 ||
                   strcmp(a, "--write-chunk") == 0 ||
                   strcmp(a, "--wouldblock-every") == 0 ||
                   strcmp(a, "--alloc-fail-after") == 0 ||
                   strcmp(a, "--validation-time") == 0) {
            if (parse_ll(v, &n) != 0) {
                fprintf(stderr, "bad number for %s: %s\n", a, v);
                return -1;
            }
            if (strcmp(a, "--deadline-ms") == 0) o->deadline_ms = n;
            else if (strcmp(a, "--read-chunk") == 0) o->faults.max_read = (size_t)n;
            else if (strcmp(a, "--write-chunk") == 0) o->faults.max_write = (size_t)n;
            else if (strcmp(a, "--wouldblock-every") == 0) o->faults.wouldblock_every = (unsigned)n;
            else if (strcmp(a, "--alloc-fail-after") == 0) o->alloc_fail_after = (long)n;
            else { o->have_validation_time = 1; o->validation_time = n; }
        } else {
            fprintf(stderr, "unknown option %s\n", a);
            return -1;
        }
    }

    if (!o->attempt || !o->connect_host || !o->server_name || !o->ca_file) {
        fputs("--attempt, --connect, --server-name and --ca are required\n",
              stderr);
        return -1;
    }
    if (o->data_mode && !o->expect_file && !o->until_close) {
        fputs("data mode needs --expect or --recv-until-close\n", stderr);
        return -1;
    }
    if (o->expect_file && o->until_close) {
        fputs("--expect and --recv-until-close are exclusive\n", stderr);
        return -1;
    }
    return 0;
}

/* ── JSON event log ── */

static FILE   *g_log;
static int64_t g_t0_ms;
static const char *g_attempt = "";

typedef struct {
    char   buf[4096];
    size_t len;
} jbuf;

static void jb_raw(jbuf *j, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (j->len >= sizeof(j->buf)) return;
    va_start(ap, fmt);
    n = vsnprintf(j->buf + j->len, sizeof(j->buf) - j->len, fmt, ap);
    va_end(ap);
    if (n > 0) j->len += (size_t)n;
    if (j->len >= sizeof(j->buf)) j->len = sizeof(j->buf) - 1;
}

static void jb_string(jbuf *j, const char *s)
{
    jb_raw(j, "\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (c == '"' || c == '\\') jb_raw(j, "\\%c", c);
        else if (c < 0x20) jb_raw(j, "\\u%04x", c);
        else jb_raw(j, "%c", c);
    }
    jb_raw(j, "\"");
}

static void jb_str(jbuf *j, const char *key, const char *val)
{
    jb_raw(j, ",\"%s\":", key);
    jb_string(j, val);
}

static void jb_int(jbuf *j, const char *key, long long val)
{
    jb_raw(j, ",\"%s\":%lld", key, val);
}

static void jb_bool(jbuf *j, const char *key, int val)
{
    jb_raw(j, ",\"%s\":%s", key, val ? "true" : "false");
}

static void jb_begin(jbuf *j, const char *event)
{
    j->len = 0;
    jb_raw(j, "{\"t_ms\":%lld,\"attempt\":",
           (long long)(host_monotonic_ms() - g_t0_ms));
    jb_string(j, g_attempt);
    jb_str(j, "event", event);
}

static void jb_emit(jbuf *j)
{
    jb_raw(j, "}\n");
    fputs(j->buf, g_log);
    fflush(g_log);
}

/* ── Names for diagnostics ── */

static const char *state_name(MacTLS_State s)
{
    static const char *names[] = { "Idle", "Connecting", "Handshaking",
                                   "Connected", "Closing", "Closed", "Error" };
    return (unsigned)s < 7 ? names[s] : "?";
}

static const char *mac_error_name(MacTLS_Error e)
{
    static const char *names[] = { "OK", "Memory", "DNS", "Connect",
                                   "Handshake", "Certificate", "Read",
                                   "Write", "Closed", "OT", "Entropy" };
    return (unsigned)e < 11 ? names[e] : "?";
}

static const char *hs_state_name(tls13_hs_state s)
{
    static const char *names[] = { "SendClientHello", "SendCCS",
        "RecvServerHello", "RecvEncryptedExtensions", "RecvCertRequestOrCert",
        "RecvCertificate", "RecvCertificateVerify", "RecvFinished",
        "SendFinished", "Complete" };
    return (unsigned)s < 10 ? names[s] : "?";
}

/* ── Small helpers ── */

static unsigned char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    size_t cap = 0, n = 0, got;

    if (f == NULL) return NULL;
    for (;;) {
        if (n == cap) {
            cap = cap ? cap * 2 : 4096;
            buf = (unsigned char *)realloc(buf, cap);
            if (buf == NULL) { fclose(f); return NULL; }
        }
        got = fread(buf + n, 1, cap - n, f);
        if (got == 0) break;
        n += got;
    }
    fclose(f);
    *len = n;
    if (buf == NULL) buf = (unsigned char *)malloc(1);
    return buf;
}

static void nap(void)
{
    struct timespec ts = { 0, 1000000 };   /* 1 ms */

    nanosleep(&ts, NULL);
}

/* ── The attempt ── */

typedef struct {
    outcome        result;
    const char    *phase;        /* where the attempt ended */
    int            reached_handshake;
    int            connected;
    const char    *close_cause;  /* alert, eof, reset or "" */
    unsigned long  sent;
    unsigned long  received;
} attempt;

/*
 * A completed Closed state carries no reason of its own, so work it out
 * from what the transport saw: a FIN or reset means the TCP connection
 * ended, otherwise the peer sent a TLS alert (close_notify) and the
 * socket was still open.
 */
static const char *close_cause(void)
{
    const host_transport_stats *st = host_transport_get_stats();

    if (st->reset_seen) return "reset";
    if (st->eof_seen) return "eof";
    return "alert";
}

static outcome classify_failure(const MacTLS_Context *ctx, const attempt *at)
{
    const host_transport_stats *st = host_transport_get_stats();

    switch (MacTLS_GetError(ctx)) {
    case kMacTLS_ErrEntropy:     return OUT_ENTROPY_ERROR;
    case kMacTLS_ErrMemory:      return OUT_MEMORY_ERROR;
    case kMacTLS_ErrCertificate: return OUT_CERTIFICATE_ERROR;
    default:                     break;
    }
    if (st->reset_seen) {
        return at->reached_handshake ? OUT_PEER_RESET : OUT_CONNECT_ERROR;
    }
    if (!at->reached_handshake) return OUT_CONNECT_ERROR;
    if (st->eof_seen) return OUT_PEER_EOF;
    return OUT_HANDSHAKE_ERROR;
}

static void log_result(const options *o, attempt *at, MacTLS_Context *ctx,
                       const char *detail)
{
    const host_transport_stats *st = host_transport_get_stats();
    jbuf j;

    jb_begin(&j, "result");
    jb_str(&j, "outcome", outcome_name(at->result));
    jb_int(&j, "exit", at->result);
    jb_str(&j, "phase", at->phase);
    if (detail != NULL) jb_str(&j, "detail", detail);
    jb_str(&j, "server_name", o->server_name);
    jb_str(&j, "close_cause", at->close_cause);
    jb_int(&j, "bytes_sent", (long long)at->sent);
    jb_int(&j, "bytes_received", (long long)at->received);
    jb_int(&j, "connections", (long long)st->connects);
    jb_bool(&j, "tls12_fallback_attempted", st->connects > 1);
    jb_int(&j, "wire_bytes_sent", (long long)st->bytes_sent);
    jb_int(&j, "wire_bytes_received", (long long)st->bytes_received);
    jb_int(&j, "wouldblocks_injected", (long long)st->wouldblocks_injected);
    jb_bool(&j, "peer_eof", st->eof_seen);
    jb_bool(&j, "peer_reset", st->reset_seen);
    jb_int(&j, "socket_errno", st->last_errno);
    if (ctx != NULL) {
        int be = MacTLS_GetBearSSLError(ctx);
        const char *name = find_error_name(be, NULL);

        jb_str(&j, "state", state_name(MacTLS_GetState(ctx)));
        jb_str(&j, "mac_error", mac_error_name(MacTLS_GetError(ctx)));
        jb_int(&j, "bearssl_error", be);
        if (name != NULL) jb_str(&j, "bearssl_error_name", name);
        if ((be & 0x10000) != 0) {
            jb_int(&j, "alert_level", (be >> 8) & 0xFF);
            jb_int(&j, "alert_description", be & 0xFF);
        }
        jb_int(&j, "ot_error", (long long)MacTLS_GetOTError(ctx));
        jb_str(&j, "tls13_state", hs_state_name(ctx->hs13.state));
        if (at->connected) {
            jb_str(&j, "tls_version",
                   MacTLS_GetVersion(ctx) == kMacTLS_Version13 ? "1.3" : "1.2");
            if (MacTLS_GetVersion(ctx) == kMacTLS_Version13) {
                jb_raw(&j, ",\"cipher_suite\":\"0x%04x\"",
                       (unsigned)ctx->hs13.cipher_suite);
            }
        }
    }
    jb_emit(&j);
}

static void run_attempt(const options *o, attempt *at, MacTLS_Context *ctx,
                        const unsigned char *send_buf, size_t send_len,
                        const unsigned char *expect, size_t expect_len,
                        FILE *out, const char **detail)
{
    int64_t deadline = host_monotonic_ms() + o->deadline_ms;
    MacTLS_State last = (MacTLS_State)-1;
    unsigned char rbuf[4096];

    for (;;) {
        MacTLS_State st;
        int progress = 0;

        if (host_monotonic_ms() >= deadline) {
            at->result = OUT_TIMEOUT;
            return;
        }

        st = MacTLS_Pump(ctx);
        if (st != last) {
            jbuf j;

            jb_begin(&j, "state");
            jb_str(&j, "state", state_name(st));
            jb_str(&j, "tls13_state", hs_state_name(ctx->hs13.state));
            jb_emit(&j);
            last = st;
        }
        if (st == kMacTLS_Connecting && strcmp(at->phase, "setup") == 0) {
            at->phase = "connect";
        }
        if (!at->reached_handshake && st == kMacTLS_Handshaking) {
            at->reached_handshake = 1;
            at->phase = "handshake";
        }

        if (st == kMacTLS_Error) {
            at->result = classify_failure(ctx, at);
            return;
        }

        if (st == kMacTLS_Connected && !at->connected) {
            jbuf j;

            at->connected = 1;
            at->reached_handshake = 1;
            at->phase = o->data_mode ? "data" : "handshake";
            jb_begin(&j, "connected");
            jb_str(&j, "tls_version",
                   MacTLS_GetVersion(ctx) == kMacTLS_Version13 ? "1.3" : "1.2");
            if (MacTLS_GetVersion(ctx) == kMacTLS_Version13) {
                jb_raw(&j, ",\"cipher_suite\":\"0x%04x\"",
                       (unsigned)ctx->hs13.cipher_suite);
            }
            jb_emit(&j);
            if (MacTLS_GetVersion(ctx) != kMacTLS_Version13 && !o->allow_tls12) {
                at->result = OUT_TLS12_FALLBACK;
                return;
            }
            if (!o->data_mode) {
                at->result = OUT_SUCCESS;
                return;
            }
        }

        if ((st == kMacTLS_Connected || st == kMacTLS_Closed) && at->connected) {
            int n;

            if (st == kMacTLS_Connected && at->sent < send_len) {
                size_t chunk = send_len - at->sent;

                if (chunk > 16384) chunk = 16384;
                n = MacTLS_Write(ctx, send_buf + at->sent, chunk);
                if (n < 0) {
                    at->result = classify_failure(ctx, at);
                    *detail = "write failed";
                    return;
                }
                if (n > 0) {
                    at->sent += (unsigned long)n;
                    progress = 1;
                }
            }

            while ((n = MacTLS_Read(ctx, rbuf, sizeof(rbuf))) > 0) {
                progress = 1;
                if (expect != NULL) {
                    size_t take = (size_t)n;

                    if (at->received + take > expect_len ||
                        memcmp(rbuf, expect + at->received, take) != 0) {
                        at->received += (unsigned long)take;
                        at->result = OUT_DATA_MISMATCH;
                        *detail = at->received > expect_len
                                      ? "more data than expected"
                                      : "bytes differ from expected";
                        return;
                    }
                }
                if (out != NULL) fwrite(rbuf, 1, (size_t)n, out);
                at->received += (unsigned long)n;
            }

            if (expect != NULL && at->received == expect_len &&
                at->sent == send_len) {
                at->result = OUT_SUCCESS;
                return;
            }
        }

        if (st == kMacTLS_Closed) {
            at->close_cause = close_cause();
            if (o->until_close && at->connected &&
                strcmp(at->close_cause, "alert") == 0) {
                /* close_notify; a bare FIN could be a truncated response. */
                at->result = OUT_SUCCESS;
            } else if (strcmp(at->close_cause, "reset") == 0) {
                at->result = OUT_PEER_RESET;
            } else if (strcmp(at->close_cause, "eof") == 0) {
                at->result = OUT_PEER_EOF;
            } else {
                at->result = OUT_PEER_ALERT;
            }
            return;
        }

        if (!progress) nap();
    }
}

int main(int argc, char **argv)
{
    options o;
    attempt at;
    ta_set tas;
    char err[256] = "";
    MacTLS_Config *cfg = NULL;
    MacTLS_Context *ctx = NULL;
    unsigned char *send_buf = NULL, *expect = NULL;
    size_t send_len = 0, expect_len = 0;
    FILE *out = NULL;
    const char *detail = NULL;

    if (parse_options(argc, argv, &o) != 0) {
        usage();
        return OUT_USAGE;
    }

    signal(SIGPIPE, SIG_IGN);
    g_t0_ms = host_monotonic_ms();
    g_attempt = o.attempt;
    g_log = stdout;
    if (o.log_file != NULL && (g_log = fopen(o.log_file, "w")) == NULL) {
        fprintf(stderr, "cannot open log %s\n", o.log_file);
        return OUT_USAGE;
    }

    memset(&at, 0, sizeof(at));
    memset(&tas, 0, sizeof(tas));
    at.phase = "setup";
    at.close_cause = "";

    {
        jbuf j;

        jb_begin(&j, "start");
        jb_str(&j, "mode", o.data_mode ? "data" : "handshake");
        jb_str(&j, "connect_host", o.connect_host);
        jb_int(&j, "port", o.port);
        jb_str(&j, "server_name", o.server_name);
        jb_int(&j, "deadline_ms", o.deadline_ms);
        jb_str(&j, "entropy", o.entropy == ENTROPY_OS ? "os" :
                              o.entropy == ENTROPY_NONE ? "none" : "fail");
        jb_int(&j, "read_chunk", (long long)o.faults.max_read);
        jb_int(&j, "write_chunk", (long long)o.faults.max_write);
        jb_int(&j, "wouldblock_every", o.faults.wouldblock_every);
        if (o.have_validation_time) jb_int(&j, "validation_time", o.validation_time);
        jb_emit(&j);
    }

    if (ta_load_pem_file(o.ca_file, &tas, err, sizeof(err)) != 0) {
        at.result = OUT_SETUP_ERROR;
        detail = err;
        goto finish;
    }
    if (o.send_file != NULL &&
        (send_buf = slurp(o.send_file, &send_len)) == NULL) {
        snprintf(err, sizeof(err), "cannot read %s", o.send_file);
        at.result = OUT_SETUP_ERROR;
        detail = err;
        goto finish;
    }
    if (o.expect_file != NULL &&
        (expect = slurp(o.expect_file, &expect_len)) == NULL) {
        snprintf(err, sizeof(err), "cannot read %s", o.expect_file);
        at.result = OUT_SETUP_ERROR;
        detail = err;
        goto finish;
    }
    if (o.out_file != NULL && (out = fopen(o.out_file, "wb")) == NULL) {
        snprintf(err, sizeof(err), "cannot write %s", o.out_file);
        at.result = OUT_SETUP_ERROR;
        detail = err;
        goto finish;
    }

    host_transport_set_faults(&o.faults);
    host_transport_reset_stats();
    MacTLS_Init();
    if (o.entropy == ENTROPY_OS) {
        MacTLS_SetEntropyProvider(host_entropy_os_random, NULL);
    } else if (o.entropy == ENTROPY_FAIL) {
        MacTLS_SetEntropyProvider(host_entropy_fail, NULL);
    }
    if (o.alloc_fail_after >= 0) host_alloc_fail_after(o.alloc_fail_after);

    cfg = MacTLS_ConfigCreate();
    if (cfg == NULL) {
        at.result = OUT_MEMORY_ERROR;
        detail = "config allocation failed";
        goto finish;
    }
    cfg->custom_tas = tas.tas;
    cfg->custom_tas_count = tas.count;
    cfg->connect_host = o.connect_host;
    if (o.have_validation_time) {
        host_unix_to_bearssl_time(o.validation_time, &cfg->validation_days,
                                  &cfg->validation_seconds);
        cfg->validation_time_set = true;
    }

    ctx = MacTLS_CreateWithConfig(o.server_name, o.port, cfg);
    if (ctx == NULL) {
        at.result = OUT_MEMORY_ERROR;
        detail = "context allocation failed";
        goto finish;
    }

    run_attempt(&o, &at, ctx, send_buf, send_len, expect, expect_len, out,
                &detail);

finish:
    log_result(&o, &at, ctx, detail);
    if (ctx != NULL) MacTLS_Close(ctx);
    if (cfg != NULL) MacTLS_ConfigFree(cfg);
    if (out != NULL) fclose(out);
    ta_free(&tas);
    free(send_buf);
    free(expect);
    MacTLS_Shutdown();
    return (int)at.result;
}
