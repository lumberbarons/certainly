/*
 * perf_client.c — workload driver and meter for the Certainly performance
 * harness.
 *
 * Runs one workload against perf_peer.py through the public API, the way an
 * application's event loop would, and prints a single JSON "perf" line.
 * The meter is built from quantities that mean the same on a laptop and a
 * PowerPC Mac, because wall-clock speed does not carry over between them:
 *
 *   - bytes the library copies itself (perf_memtrack.h) and calls made into
 *     the transport, per payload byte
 *   - the largest amount of work and time one MacTLS_Pump call does, since
 *     a long call freezes the caller's event loop
 *   - Memory Manager use, including anything left after MacTLS_Close
 *   - instructions retired inside library calls where the OS reports them
 *     (macOS), otherwise time inside library calls
 *
 * Only the public API and the trust-anchor field of the config are used, so
 * the same client measures any revision of the library.
 *
 * Build and run through tests/host/Makefile (make perf-client) and
 * tests/perf/run-perf.sh.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "certainly_internal.h"
#include "host_platform.h"
#include "perf_memtrack.h"
#include "trust_anchors.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <libproc.h>
#include <sys/resource.h>
#endif

#undef memcpy
#undef memmove

#define PATTERN_MOD 251

typedef enum { MODE_HANDSHAKE, MODE_GET, MODE_PUT } workload;

#define HS_STATES 10   /* kTLS13_SendClientHello .. kTLS13_Complete */

typedef struct {
    workload mode;
    uint16_t port;
    const char *ca_file;
    uint64_t bytes;
    size_t   chunk;       /* peer write size, i.e. TLS record size */
    size_t   read_buf;    /* application MacTLS_Read size */
    size_t   write_buf;   /* application MacTLS_Write size */
    int      repeat;
    int      verify;
    int64_t  deadline_ms;
    host_transport_faults faults;
} options;

/* ── Clocks and instruction counters ── */

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t instructions(void)
{
#ifdef __APPLE__
    struct rusage_info_v4 ri;

    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ri) == 0) {
        return ri.ri_instructions;
    }
#endif
    return 0;
}

/* Instructions the sampling itself adds between two consecutive reads. */
static uint64_t g_sample_overhead;
static int      g_have_instructions;

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return (x > y) - (x < y);
}

static void calibrate_instructions(void)
{
    uint64_t deltas[101];
    int i;

    if (instructions() == 0) return;
    g_have_instructions = 1;
    for (i = 0; i < 101; i++) {
        uint64_t a = instructions();
        uint64_t b = instructions();

        deltas[i] = b - a;
    }
    qsort(deltas, 101, sizeof(deltas[0]), cmp_u64);
    g_sample_overhead = deltas[50];
}

/* ── Phase accounting ── */

typedef struct {
    uint64_t wall_ns;       /* start to finish, including waiting on the peer */
    uint64_t lib_ns;        /* inside MacTLS_* calls only */
    uint64_t lib_instr;     /* retired inside MacTLS_* calls, overhead removed */
    uint64_t pumps;
    uint64_t idle_pumps;    /* pump calls that moved nothing on the wire */
    uint64_t reads, writes;
    uint64_t read_bytes, write_bytes;
    uint64_t max_pump_ns;
    uint64_t max_pump_copy; /* most bytes copied by one pump call */
    uint64_t max_pump_wire; /* most wire bytes moved by one pump call */
    uint64_t max_pump_instr;
    /* Pump calls grouped by the TLS 1.3 handshake state they started in. */
    uint64_t step_pumps[HS_STATES];
    uint64_t step_instr[HS_STATES];
    uint64_t step_max_instr[HS_STATES];
    uint64_t *pump_ns;      /* every pump call, for percentiles */
    size_t    pump_count, pump_cap;
    perf_copy_counters copies;
    host_transport_stats wire;
} phase;

static void add_sample(phase *p, uint64_t ns)
{
    if (p->pump_count == p->pump_cap) {
        p->pump_cap = p->pump_cap ? p->pump_cap * 2 : 1024;
        p->pump_ns = (uint64_t *)realloc(p->pump_ns, p->pump_cap * sizeof(uint64_t));
        if (p->pump_ns == NULL) {
            fputs("out of memory recording samples\n", stderr);
            exit(22);
        }
    }
    p->pump_ns[p->pump_count++] = ns;
}

static uint64_t copied_now(void)
{
    return perf_copies.memcpy_bytes + perf_copies.memmove_bytes;
}

static uint64_t wire_now(void)
{
    const host_transport_stats *w = host_transport_get_stats();

    return w->bytes_sent + w->bytes_received;
}

typedef struct {
    uint64_t t0, i0, c0, w0;
} call_mark;

static call_mark mark_begin(void)
{
    call_mark m;

    m.c0 = copied_now();
    m.w0 = wire_now();
    m.i0 = instructions();
    m.t0 = now_ns();
    return m;
}

/* Close a library call: time first so sampling stays outside the timed span. */
static uint64_t mark_end(phase *p, const call_mark *m, uint64_t *copied,
                         uint64_t *wire, uint64_t *instr)
{
    uint64_t t1 = now_ns();
    uint64_t i1 = instructions();
    uint64_t dt = t1 - m->t0;

    p->lib_ns += dt;
    *instr = 0;
    if (g_have_instructions && i1 - m->i0 > g_sample_overhead) {
        *instr = i1 - m->i0 - g_sample_overhead;
        p->lib_instr += *instr;
    }
    *copied = copied_now() - m->c0;
    *wire = wire_now() - m->w0;
    return dt;
}

static MacTLS_State timed_pump(MacTLS_Context *ctx, phase *p)
{
    unsigned step = (unsigned)ctx->hs13.state;
    call_mark m = mark_begin();
    MacTLS_State st = MacTLS_Pump(ctx);
    uint64_t copied, wire, instr, dt = mark_end(p, &m, &copied, &wire, &instr);

    p->pumps++;
    if (step < HS_STATES) {
        p->step_pumps[step]++;
        p->step_instr[step] += instr;
        if (instr > p->step_max_instr[step]) p->step_max_instr[step] = instr;
    }
    if (instr > p->max_pump_instr) p->max_pump_instr = instr;
    if (wire == 0) p->idle_pumps++;
    if (dt > p->max_pump_ns) p->max_pump_ns = dt;
    if (copied > p->max_pump_copy) p->max_pump_copy = copied;
    if (wire > p->max_pump_wire) p->max_pump_wire = wire;
    add_sample(p, dt);
    return st;
}

static int timed_read(MacTLS_Context *ctx, phase *p, void *buf, size_t len)
{
    call_mark m = mark_begin();
    int n = MacTLS_Read(ctx, buf, len);
    uint64_t copied, wire, instr;

    mark_end(p, &m, &copied, &wire, &instr);
    p->reads++;
    if (n > 0) p->read_bytes += (uint64_t)n;
    return n;
}

static int timed_write(MacTLS_Context *ctx, phase *p, const void *buf, size_t len)
{
    call_mark m = mark_begin();
    int n = MacTLS_Write(ctx, buf, len);
    uint64_t copied, wire, instr;

    mark_end(p, &m, &copied, &wire, &instr);
    p->writes++;
    if (n > 0) p->write_bytes += (uint64_t)n;
    return n;
}

/* Snapshots of the global counters, so a phase can report only its own. */
typedef struct {
    uint64_t t0;
    perf_copy_counters copies;
    host_transport_stats wire;
} phase_start;

static phase_start phase_begin(void)
{
    phase_start s;

    s.t0 = now_ns();
    s.copies = perf_copies;
    s.wire = *host_transport_get_stats();
    return s;
}

static void phase_end(phase *p, const phase_start *s)
{
    const host_transport_stats *w = host_transport_get_stats();

    p->wall_ns += now_ns() - s->t0;
    p->copies.memcpy_calls += perf_copies.memcpy_calls - s->copies.memcpy_calls;
    p->copies.memcpy_bytes += perf_copies.memcpy_bytes - s->copies.memcpy_bytes;
    p->copies.memmove_calls += perf_copies.memmove_calls - s->copies.memmove_calls;
    p->copies.memmove_bytes += perf_copies.memmove_bytes - s->copies.memmove_bytes;
    p->wire.bytes_sent += w->bytes_sent - s->wire.bytes_sent;
    p->wire.bytes_received += w->bytes_received - s->wire.bytes_received;
    p->wire.send_calls += w->send_calls - s->wire.send_calls;
    p->wire.recv_calls += w->recv_calls - s->wire.recv_calls;
    p->wire.send_data_calls += w->send_data_calls - s->wire.send_data_calls;
    p->wire.recv_data_calls += w->recv_data_calls - s->wire.recv_data_calls;
    p->wire.wouldblocks_injected += w->wouldblocks_injected - s->wire.wouldblocks_injected;
}

/* ── Output ── */

static uint64_t percentile(phase *p, int pct)
{
    size_t idx;

    if (p->pump_count == 0) return 0;
    qsort(p->pump_ns, p->pump_count, sizeof(uint64_t), cmp_u64);
    idx = (p->pump_count * (size_t)pct + 99) / 100;
    if (idx > 0) idx--;
    if (idx >= p->pump_count) idx = p->pump_count - 1;
    return p->pump_ns[idx];
}

static void emit_phase(const char *name, phase *p, int last)
{
    int i;

    printf("\"%s\":{"
           "\"wall_us\":%llu,\"lib_us\":%llu,\"lib_instructions\":%llu,"
           "\"pumps\":%llu,\"idle_pumps\":%llu,\"reads\":%llu,\"writes\":%llu,"
           "\"read_bytes\":%llu,\"write_bytes\":%llu,"
           "\"pump_p50_us\":%llu,\"pump_p99_us\":%llu,\"pump_max_us\":%llu,"
           "\"pump_max_instructions\":%llu,"
           "\"pump_max_copy_bytes\":%llu,\"pump_max_wire_bytes\":%llu,"
           "\"memcpy_calls\":%llu,\"memcpy_bytes\":%llu,"
           "\"memmove_calls\":%llu,\"memmove_bytes\":%llu,"
           "\"send_calls\":%lu,\"recv_calls\":%lu,"
           "\"send_data_calls\":%lu,\"recv_data_calls\":%lu,"
           "\"wire_sent\":%lu,\"wire_received\":%lu,\"wouldblocks\":%lu,",
           name,
           (unsigned long long)(p->wall_ns / 1000),
           (unsigned long long)(p->lib_ns / 1000),
           (unsigned long long)p->lib_instr,
           (unsigned long long)p->pumps, (unsigned long long)p->idle_pumps,
           (unsigned long long)p->reads, (unsigned long long)p->writes,
           (unsigned long long)p->read_bytes, (unsigned long long)p->write_bytes,
           (unsigned long long)(percentile(p, 50) / 1000),
           (unsigned long long)(percentile(p, 99) / 1000),
           (unsigned long long)(p->max_pump_ns / 1000),
           (unsigned long long)p->max_pump_instr,
           (unsigned long long)p->max_pump_copy,
           (unsigned long long)p->max_pump_wire,
           p->copies.memcpy_calls, p->copies.memcpy_bytes,
           p->copies.memmove_calls, p->copies.memmove_bytes,
           p->wire.send_calls, p->wire.recv_calls,
           p->wire.send_data_calls, p->wire.recv_data_calls,
           p->wire.bytes_sent, p->wire.bytes_received,
           p->wire.wouldblocks_injected);

    /* Cost by the handshake state each pump call started in: which step of
     * the protocol is heavy, and which is the longest single stall. */
    fputs("\"steps\":[", stdout);
    for (i = 0; i < HS_STATES; i++) {
        printf("%s{\"pumps\":%llu,\"instructions\":%llu,\"max_instructions\":%llu}",
               i ? "," : "", (unsigned long long)p->step_pumps[i],
               (unsigned long long)p->step_instr[i],
               (unsigned long long)p->step_max_instr[i]);
    }
    printf("]}%s", last ? "" : ",");
}

/* ── Workload ── */

typedef struct {
    int      ok;
    const char *failure;
    int      tls13;
    uint64_t verified_bytes;
    char     library[96];   /* the library's own account of a failure */
} outcome;

static void fail(outcome *o, const char *why)
{
    if (o->ok) {
        o->ok = 0;
        o->failure = why;
    }
}

static void idle_wait(void)
{
    usleep(50);
}

static int expired(int64_t deadline)
{
    return host_monotonic_ms() >= deadline;
}

/* Send a whole buffer, pumping so the library can drain what it accepted. */
static int send_all(MacTLS_Context *ctx, phase *p, const unsigned char *buf,
                    size_t len, int64_t deadline)
{
    size_t sent = 0;

    while (sent < len) {
        MacTLS_State st;
        int n = timed_write(ctx, p, buf + sent, len - sent);

        if (n < 0) return -1;
        sent += (size_t)n;
        st = timed_pump(ctx, p);
        if (st == kMacTLS_Error) return -1;
        if (n == 0) idle_wait();
        if (expired(deadline)) return -1;
    }
    return 0;
}

static int check_pattern(const unsigned char *buf, size_t n, uint64_t offset)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (buf[i] != (unsigned char)((offset + i) % PATTERN_MOD)) return 0;
    }
    return 1;
}

static void run_connection(const options *opt, MacTLS_Config *cfg,
                           phase *hs, phase *xfer, phase *cl,
                           unsigned char *rbuf, const unsigned char *pattern,
                           outcome *out)
{
    MacTLS_Context *ctx;
    MacTLS_State st;
    char cmd[64];
    phase_start ps;
    int64_t deadline = host_monotonic_ms() + opt->deadline_ms;
    uint64_t done = 0, wire_before;

    ps = phase_begin();
    ctx = MacTLS_CreateWithConfig("127.0.0.1", opt->port, cfg);
    if (ctx == NULL) {
        fail(out, "context allocation failed");
        return;
    }
    st = MacTLS_GetState(ctx);
    while (st != kMacTLS_Connected && st != kMacTLS_Error) {
        if (expired(deadline)) {
            fail(out, "handshake timed out");
            break;
        }
        wire_before = wire_now();
        st = timed_pump(ctx, hs);
        if (st != kMacTLS_Connected && st != kMacTLS_Error &&
            wire_now() == wire_before) {
            idle_wait();
        }
    }
    phase_end(hs, &ps);
    if (!out->ok) goto done;
    if (st != kMacTLS_Connected) {
        static char why[96];

        snprintf(why, sizeof(why),
                 "handshake failed (MacTLS error %d, BearSSL error %d, OT error %d)",
                 (int)MacTLS_GetError(ctx), MacTLS_GetBearSSLError(ctx),
                 (int)MacTLS_GetOTError(ctx));
        fail(out, why);
        goto done;
    }
    out->tls13 = MacTLS_GetVersion(ctx) == kMacTLS_Version13;

    ps = phase_begin();
    switch (opt->mode) {
    case MODE_HANDSHAKE:
        snprintf(cmd, sizeof(cmd), "NOP\n");
        break;
    case MODE_GET:
        snprintf(cmd, sizeof(cmd), "GET %llu %zu\n",
                 (unsigned long long)opt->bytes, opt->chunk);
        break;
    case MODE_PUT:
        snprintf(cmd, sizeof(cmd), "PUT %llu\n", (unsigned long long)opt->bytes);
        break;
    }
    if (send_all(ctx, xfer, (const unsigned char *)cmd, strlen(cmd), deadline) != 0) {
        fail(out, "could not send the command");
        phase_end(xfer, &ps);
        goto done;
    }

    if (opt->mode == MODE_GET) {
        while (done < opt->bytes) {
            int n;
            uint64_t before = done;

            st = timed_pump(ctx, xfer);
            while ((n = timed_read(ctx, xfer, rbuf, opt->read_buf)) > 0) {
                if (opt->verify && !check_pattern(rbuf, (size_t)n, done)) {
                    fail(out, "payload differs from the pattern");
                }
                done += (uint64_t)n;
                if (done >= opt->bytes) break;
            }
            if (!out->ok) break;
            if (st == kMacTLS_Error ||
                (st == kMacTLS_Closed && done < opt->bytes)) {
                fail(out, "connection ended before all bytes arrived");
                break;
            }
            if (done == before) idle_wait();
            if (expired(deadline)) {
                fail(out, "transfer timed out");
                break;
            }
        }
        if (out->ok && done != opt->bytes) fail(out, "wrong byte count");
        out->verified_bytes += opt->verify ? done : 0;
    } else if (opt->mode == MODE_PUT) {
        while (done < opt->bytes) {
            size_t want = opt->write_buf;
            int n;

            if (want > opt->bytes - done) want = (size_t)(opt->bytes - done);
            n = timed_write(ctx, xfer, pattern + (done % PATTERN_MOD), want);
            if (n < 0) {
                fail(out, "write failed");
                break;
            }
            done += (uint64_t)n;
            st = timed_pump(ctx, xfer);
            if (st == kMacTLS_Error) {
                fail(out, "connection failed during upload");
                break;
            }
            if (n == 0) idle_wait();
            if (expired(deadline)) {
                fail(out, "upload timed out");
                break;
            }
        }
        if (out->ok) {
            int got = 0;

            while (got < 3) {
                int n;

                st = timed_pump(ctx, xfer);
                n = timed_read(ctx, xfer, rbuf, 3 - got);
                if (n > 0) got += n;
                else idle_wait();
                if (st == kMacTLS_Error || expired(deadline)) {
                    fail(out, "no acknowledgement for the upload");
                    break;
                }
            }
        }
    }
    phase_end(xfer, &ps);

done:
    if (!out->ok && out->library[0] == '\0') {
        snprintf(out->library, sizeof(out->library),
                 "state %d, MacTLS error %d, BearSSL error %d, OT error %d",
                 (int)MacTLS_GetState(ctx), (int)MacTLS_GetError(ctx),
                 MacTLS_GetBearSSLError(ctx), (int)MacTLS_GetOTError(ctx));
    }
    ps = phase_begin();
    {
        call_mark m = mark_begin();
        uint64_t copied, wire, instr;

        MacTLS_Close(ctx);
        mark_end(cl, &m, &copied, &wire, &instr);
    }
    phase_end(cl, &ps);
}

/* ── Setup ── */

static int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
}

static void usage(void)
{
    fputs(
"usage: perf_client --port N --ca FILE --mode handshake|get|put [options]\n"
"\n"
"  --bytes N          payload size for get/put\n"
"  --chunk N          peer write size for get (sets the TLS record size)\n"
"  --read-buf N       application MacTLS_Read size (default 4096)\n"
"  --write-buf N      application MacTLS_Write size (default 4096)\n"
"  --repeat N         connections to make in this process (default 1)\n"
"  --verify           check every downloaded byte against the pattern\n"
"  --read-chunk N     cap bytes per transport read\n"
"  --write-chunk N    cap bytes per transport write\n"
"  --wouldblock-every N   report no-data/no-room on every Nth transport call\n"
"  --deadline-ms N    per-connection limit (default 60000)\n",
        stderr);
}

static int parse_options(int argc, char **argv, options *o)
{
    int i;

    memset(o, 0, sizeof(*o));
    o->mode = MODE_HANDSHAKE;
    o->chunk = 16384;
    o->read_buf = 4096;
    o->write_buf = 4096;
    o->repeat = 1;
    o->deadline_ms = 60000;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        uint64_t n;

        if (strcmp(a, "--verify") == 0) { o->verify = 1; continue; }
        if (v == NULL) {
            fprintf(stderr, "missing value for %s\n", a);
            return -1;
        }
        i++;
        if (strcmp(a, "--ca") == 0) { o->ca_file = v; continue; }
        if (strcmp(a, "--mode") == 0) {
            if (strcmp(v, "handshake") == 0) o->mode = MODE_HANDSHAKE;
            else if (strcmp(v, "get") == 0) o->mode = MODE_GET;
            else if (strcmp(v, "put") == 0) o->mode = MODE_PUT;
            else { fprintf(stderr, "bad --mode %s\n", v); return -1; }
            continue;
        }
        if (parse_u64(v, &n) != 0) {
            fprintf(stderr, "bad value for %s: %s\n", a, v);
            return -1;
        }
        if (strcmp(a, "--port") == 0 && n >= 1 && n <= 65535) o->port = (uint16_t)n;
        else if (strcmp(a, "--bytes") == 0) o->bytes = n;
        else if (strcmp(a, "--chunk") == 0 && n >= 1) o->chunk = (size_t)n;
        else if (strcmp(a, "--read-buf") == 0 && n >= 1) o->read_buf = (size_t)n;
        else if (strcmp(a, "--write-buf") == 0 && n >= 1) o->write_buf = (size_t)n;
        else if (strcmp(a, "--repeat") == 0 && n >= 1) o->repeat = (int)n;
        else if (strcmp(a, "--deadline-ms") == 0) o->deadline_ms = (int64_t)n;
        else if (strcmp(a, "--read-chunk") == 0) o->faults.max_read = (size_t)n;
        else if (strcmp(a, "--write-chunk") == 0) o->faults.max_write = (size_t)n;
        else if (strcmp(a, "--wouldblock-every") == 0) o->faults.wouldblock_every = (unsigned)n;
        else {
            fprintf(stderr, "unknown or invalid option %s\n", a);
            return -1;
        }
    }
    if (o->port == 0 || o->ca_file == NULL) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    options opt;
    ta_set tas;
    char err[160];
    MacTLS_Config *cfg;
    phase hs, xfer, cl;
    outcome out;
    unsigned char *rbuf, *pattern;
    size_t i, heap_before;
    unsigned long ctx_peak;
    const host_alloc_stats *as;
    int r;

    if (parse_options(argc, argv, &opt) != 0) {
        usage();
        return 20;
    }
    if (ta_load_pem_file(opt.ca_file, &tas, err, sizeof(err)) != 0) {
        fprintf(stderr, "cannot load %s: %s\n", opt.ca_file, err);
        return 22;
    }

    memset(&hs, 0, sizeof(hs));
    memset(&xfer, 0, sizeof(xfer));
    memset(&cl, 0, sizeof(cl));
    memset(&out, 0, sizeof(out));
    out.ok = 1;

    rbuf = (unsigned char *)malloc(opt.read_buf > 16 ? opt.read_buf : 16);
    pattern = (unsigned char *)malloc(opt.write_buf + PATTERN_MOD);
    if (rbuf == NULL || pattern == NULL) return 22;
    for (i = 0; i < opt.write_buf + PATTERN_MOD; i++) {
        pattern[i] = (unsigned char)(i % PATTERN_MOD);
    }

    calibrate_instructions();
    host_transport_set_faults(&opt.faults);
    host_transport_reset_stats();
    MacTLS_Init();
#ifdef PERF_TRUSTED_ENTROPY
    MacTLS_SetEntropyProvider(host_entropy_os_random, NULL);
#endif
    cfg = MacTLS_ConfigCreate();
    if (cfg == NULL) return 23;
    cfg->custom_tas = tas.tas;
    cfg->custom_tas_count = tas.count;

    as = host_alloc_get_stats();
    host_alloc_reset_stats();
    heap_before = as->live_bytes;
    ctx_peak = 0;

    for (r = 0; r < opt.repeat && out.ok; r++) {
        host_alloc_reset_stats();
        run_connection(&opt, cfg, &hs, &xfer, &cl, rbuf, pattern, &out);
        if (as->peak_bytes - heap_before > ctx_peak) {
            ctx_peak = (unsigned long)(as->peak_bytes - heap_before);
        }
    }

    printf("{\"event\":\"perf\",\"ok\":%s,\"failure\":\"%s\",\"library\":\"%s\",\"tls13\":%s,"
           "\"mode\":\"%s\",\"bytes\":%llu,\"chunk\":%zu,\"read_buf\":%zu,"
           "\"write_buf\":%zu,\"repeat\":%d,\"verified\":%s,"
           "\"instruction_counts\":%s,\"heap_peak_per_connection\":%lu,"
           "\"heap_leaked\":%ld,",
           out.ok ? "true" : "false", out.failure ? out.failure : "",
           out.library, out.tls13 ? "true" : "false",
           opt.mode == MODE_HANDSHAKE ? "handshake" :
           opt.mode == MODE_GET ? "get" : "put",
           (unsigned long long)opt.bytes, opt.chunk, opt.read_buf,
           opt.write_buf, opt.repeat, opt.verify ? "true" : "false",
           g_have_instructions ? "true" : "false", ctx_peak,
           (long)as->live_bytes - (long)heap_before);
    emit_phase("handshake", &hs, 0);
    emit_phase("transfer", &xfer, 0);
    emit_phase("close", &cl, 1);
    puts("}");

    MacTLS_ConfigFree(cfg);
    ta_free(&tas);
    MacTLS_Shutdown();
    return out.ok ? 0 : 10;
}
