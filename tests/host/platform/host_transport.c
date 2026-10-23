/*
 * host_transport.c — ot_transport.h on nonblocking POSIX sockets.
 *
 * Reproduces the contract the pump relies on, not Open Transport's
 * internals:
 *   send  > 0 bytes accepted (possibly fewer than asked), 0 no room,
 *         -1 error
 *   recv  > 0 bytes, 0 nothing yet, -1 once the peer has closed (orderly:
 *         ordRelReceived) or the connection failed (disconnectReceived,
 *         lastError set)
 * Faults from host_transport_set_faults() sit in front of the socket so
 * partial transfers and would-block reach the pump deterministically.
 *
 * Differences from OT: the destination must be an IP literal (no async
 * DNS), and an orderly close is only noticed once buffered data has been
 * read, where OT raises its event as soon as the FIN arrives. The pump
 * handles either order.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include "host_platform.h"
#include "ot_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <Memory.h>   /* NewPtrClear, DisposePtr */
#include <Events.h>   /* TickCount */

#define OT_TIMEDOUT_ERR (-3259)

static host_transport_faults g_faults;
static host_transport_stats  g_stats;
static unsigned              g_recv_count;
static unsigned              g_send_count;

void host_transport_set_faults(const host_transport_faults *faults)
{
    g_faults = *faults;
    g_recv_count = 0;
    g_send_count = 0;
}

void host_transport_reset_stats(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

const host_transport_stats *host_transport_get_stats(void)
{
    return &g_stats;
}

/* The socket lives in the (otherwise opaque) endpoint slot, offset by one
 * so that fd 0 stays distinguishable from "no socket". */
static int fd_of(const OTTransport *t)
{
    return (int)(intptr_t)t->endpoint - 1;
}

static int should_inject(unsigned *counter)
{
    if (g_faults.wouldblock_every == 0) return 0;
    if (++*counter % g_faults.wouldblock_every != 0) return 0;
    g_stats.wouldblocks_injected++;
    return 1;
}

static void fail_connection(OTTransport *t, int err)
{
    t->lastError = (OSStatus)-err;
    t->disconnectReceived = true;
    g_stats.reset_seen = 1;
    g_stats.last_errno = err;
}

static void fail_create(OTTransport *t, int err)
{
    t->lastError = (OSStatus)-err;
    t->state = kOTTransport_Error;
    g_stats.last_errno = err;
}

OTTransport *ot_transport_create(const char *host, uint16_t port)
{
    OTTransport *t;
    struct addrinfo hints, *ai = NULL;
    char service[8];
    int fd, flags, rc, connect_errno;

    t = (OTTransport *)NewPtrClear(sizeof(OTTransport));
    if (t == NULL) return NULL;

    t->port = port;
    t->state = kOTTransport_Idle;
    t->connect_start_ticks = (uint32_t)TickCount();
    g_stats.connect_attempts++;
    if (g_faults.single_connection && g_stats.connect_attempts > 1) {
        fail_create(t, ECANCELED);
        return t;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    snprintf(service, sizeof(service), "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &ai) != 0) {
        fail_create(t, EINVAL);
        return t;
    }

    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        fail_create(t, errno);
        freeaddrinfo(ai);
        return t;
    }
    g_stats.connects++;
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    t->endpoint = (EndpointRef)(intptr_t)(fd + 1);

    rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    connect_errno = errno;
    if (g_stats.first_local_port == 0) {
        struct sockaddr_storage local;
        socklen_t local_len = sizeof(local);

        if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
            if (local.ss_family == AF_INET)
                g_stats.first_local_port = ntohs(((struct sockaddr_in *)&local)->sin_port);
            else if (local.ss_family == AF_INET6)
                g_stats.first_local_port = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
        }
    }
    freeaddrinfo(ai);
    if (rc != 0 && connect_errno != EINPROGRESS) {
        fail_create(t, connect_errno);
        return t;
    }

    t->state = kOTTransport_Connecting;
    return t;
}

OTTransportState ot_transport_pump(OTTransport *t)
{
    switch (t->state) {

    case kOTTransport_Connecting: {
        struct pollfd pfd;
        int err = 0;
        socklen_t errlen = sizeof(err);

        if ((uint32_t)TickCount() - t->connect_start_ticks >
            OT_CONNECT_TIMEOUT_TICKS) {
            t->lastError = OT_TIMEDOUT_ERR;
            t->state = kOTTransport_Error;
            break;
        }
        pfd.fd = fd_of(t);
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) <= 0) break;
        getsockopt(pfd.fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err != 0) {
            fail_create(t, err);
            break;
        }
        t->connectComplete = true;
        t->state = kOTTransport_Connected;
        break;
    }

    case kOTTransport_Connected:
        if (t->disconnectReceived) {
            t->state = kOTTransport_Error;
            break;
        }
        if (t->ordRelReceived && !t->ordRelConsumed) {
            t->ordRelConsumed = true;
        }
        break;

    case kOTTransport_Closing: {
        char probe;
        ssize_t n = recv(fd_of(t), &probe, 1, MSG_PEEK | MSG_DONTWAIT);

        if (n == 0) t->ordRelReceived = true;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR) {
            t->disconnectReceived = true;
        }
        if (t->ordRelReceived || t->disconnectReceived) {
            t->state = kOTTransport_Closed;
        }
        break;
    }

    default:
        break;
    }

    return t->state;
}

int ot_transport_send(OTTransport *t, const void *buf, size_t len)
{
    ssize_t n;
    int flags = 0;

    if (t->state != kOTTransport_Connected) return -1;

    g_stats.send_calls++;
    if (should_inject(&g_send_count)) return 0;
    if (g_faults.max_write != 0 && len > g_faults.max_write) {
        len = g_faults.max_write;
    }
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    n = send(fd_of(t), buf, len, flags);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0;
        }
        fail_connection(t, errno);
        return -1;
    }
    g_stats.bytes_sent += (unsigned long)n;
    if (n > 0) g_stats.send_data_calls++;
    return (int)n;
}

int ot_transport_recv(OTTransport *t, void *buf, size_t len)
{
    ssize_t n;

    if (t->state != kOTTransport_Connected &&
        t->state != kOTTransport_Closing) return -1;

    g_stats.recv_calls++;
    /* Once the peer's FIN is in, nothing more can ever arrive. */
    if (t->ordRelReceived) return -1;
    if (should_inject(&g_recv_count)) return 0;
    if (g_faults.max_read != 0 && len > g_faults.max_read) {
        len = g_faults.max_read;
    }

    n = recv(fd_of(t), buf, len, 0);
    if (n > 0) {
        g_stats.bytes_received += (unsigned long)n;
        g_stats.recv_data_calls++;
        return (int)n;
    }
    if (n == 0) {
        t->ordRelReceived = true;
        g_stats.eof_seen = 1;
        return -1;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    fail_connection(t, errno);
    return -1;
}

void ot_transport_close(OTTransport *t)
{
    if (t->state == kOTTransport_Connected) {
        shutdown(fd_of(t), SHUT_WR);
        t->state = kOTTransport_Closing;
    }
}

void ot_transport_destroy(OTTransport *t)
{
    if (t == NULL) return;
    if (t->endpoint != NULL) close(fd_of(t));
    DisposePtr((Ptr)t);
}
