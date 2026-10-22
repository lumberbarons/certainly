/*
 * test_host_transport.c — the host socket adapter keeps the transport
 * contract the pump depends on.
 *
 * The pump distinguishes "no data yet" (0) from "peer closed" (-1 with
 * ordRelReceived) from "connection failed" (-1 with disconnectReceived and
 * lastError). If the adapter blurred these, conformance results from the
 * native client would not predict behaviour on Open Transport.
 *
 *   cd tests/host && make test_host_transport && ./test_host_transport
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "platform/host_platform.h"
#include "ot_transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <Memory.h>

static int failures;

#define CHECK(cond, ...) do {                                  \
    if (!(cond)) {                                             \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);            \
        printf(__VA_ARGS__);                                   \
        printf("\n");                                          \
        failures++;                                            \
    }                                                          \
} while (0)

static int listen_loopback(uint16_t *port)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        perror("listen_loopback");
        exit(2);
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

/* A connected transport and the peer's end of the same connection. */
static OTTransport *connect_pair(int lfd, uint16_t port, int *peer)
{
    OTTransport *t = ot_transport_create("127.0.0.1", port);
    int i;

    for (i = 0; i < 1000 && ot_transport_pump(t) == kOTTransport_Connecting; i++) {
        usleep(1000);
    }
    CHECK(ot_transport_pump(t) == kOTTransport_Connected, "connect failed");
    *peer = accept(lfd, NULL, NULL);
    CHECK(*peer >= 0, "accept failed");
    return t;
}

static void set_faults(size_t max_read, size_t max_write, unsigned every)
{
    host_transport_faults f = {0};

    f.max_read = max_read;
    f.max_write = max_write;
    f.wouldblock_every = every;
    host_transport_set_faults(&f);
}

/* recv until something other than "nothing yet", bounded to ~2 s. */
static int recv_settled(OTTransport *t, void *buf, size_t len)
{
    int i, n = 0;

    for (i = 0; i < 2000; i++) {
        n = ot_transport_recv(t, buf, len);
        if (n != 0) return n;
        usleep(1000);
    }
    return 0;
}

static void test_no_data_is_not_eof(int lfd, uint16_t port)
{
    int peer;
    OTTransport *t = connect_pair(lfd, port, &peer);
    char buf[8];

    set_faults(0, 0, 0);
    CHECK(ot_transport_recv(t, buf, sizeof(buf)) == 0,
          "idle connection must report 0, not an error");
    CHECK(!t->ordRelReceived && !t->disconnectReceived, "spurious close flags");

    ot_transport_close(t);
    ot_transport_destroy(t);
    close(peer);
}

static void test_partial_writes(int lfd, uint16_t port)
{
    int peer;
    OTTransport *t = connect_pair(lfd, port, &peer);
    char got[16];
    ssize_t n;

    set_faults(0, 3, 0);
    CHECK(ot_transport_send(t, "0123456789", 10) == 3,
          "write cap not applied");
    n = read(peer, got, sizeof(got));
    CHECK(n == 3 && memcmp(got, "012", 3) == 0, "peer got %zd bytes", n);

    ot_transport_close(t);
    ot_transport_destroy(t);
    close(peer);
}

static void test_partial_reads_and_wouldblock(int lfd, uint16_t port)
{
    int peer;
    OTTransport *t = connect_pair(lfd, port, &peer);
    char buf[16];
    const host_transport_stats *st;

    CHECK(write(peer, "abcdef", 6) == 6, "peer write");
    usleep(20000);

    /* Every 2nd call is reported as would-block even though data waits. */
    set_faults(2, 0, 2);
    host_transport_reset_stats();
    CHECK(ot_transport_recv(t, buf, sizeof(buf)) == 2 &&
          memcmp(buf, "ab", 2) == 0, "first read should be capped at 2");
    CHECK(ot_transport_recv(t, buf, sizeof(buf)) == 0,
          "injected would-block must return 0");
    CHECK(!t->ordRelReceived && !t->disconnectReceived,
          "would-block must not look like a close");
    CHECK(ot_transport_recv(t, buf, sizeof(buf)) == 2 &&
          memcmp(buf, "cd", 2) == 0, "data lost across would-block");
    st = host_transport_get_stats();
    CHECK(st->wouldblocks_injected == 1, "injected=%lu", st->wouldblocks_injected);

    /* Every 2nd send is refused with 0 and sends nothing. */
    set_faults(0, 0, 2);
    CHECK(ot_transport_send(t, "x", 1) == 1, "first send");
    CHECK(ot_transport_send(t, "y", 1) == 0, "injected send would-block");

    ot_transport_close(t);
    ot_transport_destroy(t);
    close(peer);
}

static void test_orderly_eof(int lfd, uint16_t port)
{
    int peer;
    OTTransport *t = connect_pair(lfd, port, &peer);
    char buf[8];
    const host_transport_stats *st;

    set_faults(0, 0, 0);
    host_transport_reset_stats();
    CHECK(write(peer, "xy", 2) == 2, "peer write");
    close(peer);

    CHECK(recv_settled(t, buf, sizeof(buf)) == 2, "buffered data comes first");
    CHECK(!t->ordRelReceived, "EOF reported before buffered data was read");
    CHECK(recv_settled(t, buf, sizeof(buf)) == -1, "EOF should be -1");
    st = host_transport_get_stats();
    CHECK(t->ordRelReceived && !t->disconnectReceived,
          "orderly EOF must set ordRelReceived only");
    CHECK(t->lastError == noErr, "orderly EOF is not an error (%d)", (int)t->lastError);
    CHECK(st->eof_seen && !st->reset_seen, "stats should record EOF");
    CHECK(ot_transport_recv(t, buf, sizeof(buf)) == -1, "EOF must be sticky");
    CHECK(ot_transport_pump(t) == kOTTransport_Connected,
          "pump must stay Connected so sends still work after a half-close");

    ot_transport_destroy(t);
}

static void test_reset(int lfd, uint16_t port)
{
    int peer;
    OTTransport *t = connect_pair(lfd, port, &peer);
    struct linger lg = { 1, 0 };
    char buf[8];
    const host_transport_stats *st;

    set_faults(0, 0, 0);
    host_transport_reset_stats();
    setsockopt(peer, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close(peer);   /* RST rather than FIN */

    CHECK(recv_settled(t, buf, sizeof(buf)) == -1, "reset should be -1");
    st = host_transport_get_stats();
    CHECK(t->disconnectReceived && !t->ordRelReceived,
          "reset must set disconnectReceived, not ordRelReceived");
    CHECK(t->lastError != noErr, "reset must leave an error code");
    CHECK(st->reset_seen && !st->eof_seen && st->last_errno != 0,
          "stats should record reset (errno %d)", st->last_errno);
    CHECK(ot_transport_pump(t) == kOTTransport_Error,
          "pump must surface the disconnect");

    ot_transport_destroy(t);
}

static void test_connect_failures(void)
{
    uint16_t dead_port;
    int lfd = listen_loopback(&dead_port);
    OTTransport *t;
    int i;

    close(lfd);   /* nothing listens here any more */
    host_transport_reset_stats();
    t = ot_transport_create("127.0.0.1", dead_port);
    for (i = 0; i < 1000 && ot_transport_pump(t) == kOTTransport_Connecting; i++) {
        usleep(1000);
    }
    CHECK(ot_transport_pump(t) == kOTTransport_Error, "refused connect not an error");
    CHECK(t->lastError != noErr, "refused connect left no error code");
    CHECK(host_transport_get_stats()->last_errno == ECONNREFUSED,
          "errno=%d", host_transport_get_stats()->last_errno);
    CHECK(ot_transport_send(t, "x", 1) == -1, "send on a failed transport");
    ot_transport_destroy(t);

    /* A name is not resolved: DNS would block the pump. */
    t = ot_transport_create("not-an-ip.invalid", 1);
    CHECK(ot_transport_pump(t) == kOTTransport_Error, "hostname accepted");
    ot_transport_destroy(t);
}

static void test_allocation_failure(void)
{
    host_alloc_fail_after(0);
    CHECK(ot_transport_create("127.0.0.1", 1) == NULL,
          "allocation failure must return NULL");
    host_alloc_fail_after(-1);
}

static void test_single_connection(int lfd, uint16_t port)
{
    host_transport_faults faults = {0};
    struct sockaddr_in address;
    socklen_t size = sizeof(address);
    struct pollfd pending = { lfd, POLLIN, 0 };
    int peer;
    OTTransport *first, *second;

    faults.single_connection = 1;
    host_transport_set_faults(&faults);
    host_transport_reset_stats();
    first = connect_pair(lfd, port, &peer);
    CHECK(getpeername(peer, (struct sockaddr *)&address, &size) == 0,
          "cannot read the peer-observed port");
    CHECK(host_transport_get_stats()->first_local_port == ntohs(address.sin_port),
          "correlation port differs from the peer's observation");
    second = ot_transport_create("127.0.0.1", port);
    CHECK(ot_transport_pump(second) == kOTTransport_Error,
          "a second socket must be refused in single-connection mode");
    CHECK(host_transport_get_stats()->connect_attempts == 2 &&
          host_transport_get_stats()->connects == 1,
          "fallback must be recorded without opening a second socket");
    CHECK(poll(&pending, 1, 0) == 0, "a reconnect reached the listener");
    CHECK(ot_transport_send(first, "x", 1) == 1, "the first connection was disturbed");
    ot_transport_destroy(second);
    ot_transport_destroy(first);
    close(peer);
    set_faults(0, 0, 0);
}

int main(void)
{
    uint16_t port;
    int lfd = listen_loopback(&port);

    test_no_data_is_not_eof(lfd, port);
    test_partial_writes(lfd, port);
    test_partial_reads_and_wouldblock(lfd, port);
    test_orderly_eof(lfd, port);
    test_reset(lfd, port);
    test_single_connection(lfd, port);
    close(lfd);
    test_connect_failures();
    test_allocation_failure();

    if (failures) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("test_host_transport: all checks passed\n");
    return 0;
}
