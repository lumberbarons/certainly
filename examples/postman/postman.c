/*
 * postman.c — Interactive HTTPS tester for Mac OS 9.
 *
 * Drives the Certainly TLS library from a classic Toolbox event loop:
 * reads URL/headers/body from the UI, builds a request, pumps the
 * handshake to completion, and displays the response.
 */

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Menus.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Events.h>
#include <Sound.h>
#include <OpenTransport.h>
#include <stdio.h>
#include <string.h>

#include "certainly.h"
#include "ui.h"
#include "http.h"
#include "seed_file.h"

int gQuit = 0;

/* Send-flow state. Only postman.c touches these. */
static MacTLS_Context *gCtx              = NULL;
static int             gSending          = 0;
static int             gCancelled        = 0;
static int             gRequestSent      = 0;
static int             gRequestIsHead    = 0;
static char            gRequestBuf[8192];
static int             gRequestLen       = 0;
static char            gResponseBuf[32768];
static int             gResponseLen      = 0;
static int             gPrevResponseLen  = 0;
/* Captured at the first Connected tick so it survives the move to Closed. */
static MacTLS_Version  gNegotiatedVersion = kMacTLS_VersionUnknown;

/* ── Send flow ──────────────────────────────────────────────────── */

static const char *tls_version_label(MacTLS_Version v)
{
    switch (v) {
    case kMacTLS_Version13: return "TLS 1.3";
    case kMacTLS_Version12: return "TLS 1.2";
    default:                return "TLS ?";
    }
}

static void format_tls_error(char *out, size_t cap)
{
    if (gCtx && MacTLS_GetError(gCtx) == kMacTLS_ErrEntropy) {
        snprintf(out, cap, "No trusted seed: provide \"%s\" (see README)",
                 kSeedFileName);
        return;
    }
    snprintf(out, cap, "TLS error: code=%d bssl=%d OT=%ld",
             gCtx ? MacTLS_GetError(gCtx)        : -1,
             gCtx ? MacTLS_GetBearSSLError(gCtx) : 0,
             gCtx ? (long)MacTLS_GetOTError(gCtx) : 0);
}

static void finalize_send(void)
{
    if (gCtx) { MacTLS_Close(gCtx); gCtx = NULL; }
    gSending         = 0;
    gCancelled       = 0;
    gRequestSent     = 0;
    gRequestLen      = 0;
    gPrevResponseLen   = 0;
    gNegotiatedVersion = kMacTLS_VersionUnknown;
    /* gResponseLen / gResponseBuf retained so the response pane
     * still reflects the last response until a new send starts. */
    ui_set_send_enabled(1);
}

static void finalize_response(int local_truncated, HttpEnd end);

static void DriveSendStep(void)
{
    MacTLS_State state;
    char         status[256];

    if (!gSending || !gCtx) return;

    if (gCancelled) {
        ui_set_status("Cancelled");
        finalize_send();
        return;
    }

    state = MacTLS_Pump(gCtx);

    switch (state) {
    case kMacTLS_Connecting:
        /* Transient — no status update. */
        break;

    case kMacTLS_Handshaking:
        ui_set_status("TLS handshake...");
        break;

    case kMacTLS_Connected: {
        if (!gRequestSent) {
            gNegotiatedVersion = MacTLS_GetVersion(gCtx);
            MacTLS_Write(gCtx, gRequestBuf, (size_t)gRequestLen);
            gRequestSent = 1;
            snprintf(status, sizeof(status),
                     "Sending request (%s)...",
                     tls_version_label(gNegotiatedVersion));
            ui_set_status(status);
        }
        int space = (int)sizeof(gResponseBuf) - gResponseLen - 1;
        if (space <= 0) {
            /* Response buffer saturated — stop waiting for Close we
             * can't drain toward. Finalize with what we have. */
            finalize_response(1, kHttpEnd_Truncated);
            return;
        }
        int n = MacTLS_Read(gCtx, gResponseBuf + gResponseLen,
                            (size_t)space);
        if (n > 0) {
            gResponseLen += n;
            /* Cheap periodic status update: only redraw when crossing
             * a 1 KB boundary, not on every byte. */
            if ((gResponseLen & ~1023) != (gPrevResponseLen & ~1023)) {
                snprintf(status, sizeof(status),
                         "Reading response (%s, %d bytes)",
                         tls_version_label(gNegotiatedVersion),
                         gResponseLen);
                ui_set_status(status);
                gPrevResponseLen = gResponseLen;
            }
        }
        break;
    }

    case kMacTLS_Closed: {
        /* Server closed — drain any residual bytes the library has
         * already decrypted into its internal buffer. */
        for (;;) {
            int space = (int)sizeof(gResponseBuf) - gResponseLen - 1;
            if (space <= 0) break;
            int n = MacTLS_Read(gCtx, gResponseBuf + gResponseLen,
                                (size_t)space);
            if (n <= 0) break;
            gResponseLen += n;
        }
        finalize_response(gResponseLen >= (int)sizeof(gResponseBuf) - 1,
                          kHttpEnd_CloseNotify);
        return;
    }

    case kMacTLS_Error:
        /* The peer vanished without a close_notify. What arrived is
         * authentic but may be a cut-off prefix; whether that matters
         * depends on the HTTP framing, so judge it there. Every other
         * error says nothing trustworthy about the response. */
        if (MacTLS_GetError(gCtx) == kMacTLS_ErrTruncated) {
            finalize_response(gResponseLen >= (int)sizeof(gResponseBuf) - 1,
                              kHttpEnd_Truncated);
            return;
        }
        format_tls_error(status, sizeof(status));
        ui_set_status(status);
        finalize_send();
        return;

    default:
        break;
    }
}

static void finalize_response(int local_truncated, HttpEnd end)
{
    const char *status_line; size_t status_len;
    const char *headers;     size_t headers_len;
    const char *body;        size_t body_len;
    const char *warning = NULL;
    char        status[320];
    HttpBodyState framing;
    HttpVerdict   verdict = kHttpVerdict_Complete;
    size_t      body_used = 0;
    size_t      off;
    int         chunked;

    if (gResponseLen == 0) {
        ui_set_status(end == kHttpEnd_CloseNotify
                      ? "Empty response"
                      : "Connection closed before any response (no TLS close_notify)");
        finalize_send();
        return;
    }

    gResponseBuf[gResponseLen] = '\0';

    off = http_final_response_offset(gResponseBuf, (size_t)gResponseLen);
    if (http_split_response(gResponseBuf + off, (size_t)gResponseLen - off,
                            &status_line, &status_len,
                            &headers,     &headers_len,
                            &body,        &body_len) != 0) {
        /* Without a complete header block there is no message to judge. */
        ui_set_status(end == kHttpEnd_Truncated
            ? "INCOMPLETE: connection closed mid-headers (no TLS close_notify)"
            : "Malformed HTTP response");
        /* Show raw first bytes so the user can see what came back. */
        int show = gResponseLen > 256 ? 256 : gResponseLen;
        ui_set_response(gResponseBuf, (size_t)show);
        finalize_send();
        return;
    }

    chunked = http_headers_is_chunked(headers, headers_len);
    framing = http_check_body_framing(status_line, status_len,
                                      headers, headers_len,
                                      body, body_len,
                                      gRequestIsHead, &body_used);

    /* When our own buffer overflowed the body is short by design; that is
     * reported as a truncation below, not as a protocol failure. */
    if (!local_truncated) {
        verdict = http_response_verdict(framing, end);
        switch (verdict) {
        case kHttpVerdict_Incomplete:
            warning = end == kHttpEnd_Truncated
                ? "INCOMPLETE: connection ended before the body was complete (no TLS close_notify)"
                : "INCOMPLETE: body is shorter than the response declared";
            break;
        case kHttpVerdict_Unverified:
            warning = "UNVERIFIED: closed without TLS close_notify, response may be cut off";
            break;
        case kHttpVerdict_Malformed:
            warning = "MALFORMED: invalid message framing";
            break;
        default:
            break;
        }
    }

    static char decoded_body[32768];
    if (chunked && framing != kHttpBody_Malformed) {
        size_t written = 0;
        /* Incomplete bodies still decode what arrived so it can be shown
         * next to the warning. */
        http_decode_chunked_ex(body, body_used, decoded_body,
                               sizeof(decoded_body), &written, NULL);
        body     = decoded_body;
        body_len = written;
    } else if (framing == kHttpBody_Malformed) {
        /* Never present bytes under a status line when their framing is
         * not trustworthy. */
        body_len = 0;
    } else if (body_used < body_len) {
        body_len = body_used;
    }

    /* Build the status-line string. A problem comes first so it cannot be
     * missed. */
    {
        size_t out_len = status_len;
        if (out_len > 128) out_len = 128;
        snprintf(status, sizeof(status), "%s%.*s  (%s%s)",
                 warning ? "[!] " : "", (int)out_len, status_line,
                 tls_version_label(gNegotiatedVersion),
                 local_truncated ? ", truncated to 32K" : "");
        if (warning) {
            size_t used = strlen(status);
            snprintf(status + used, sizeof(status) - used, " - %s", warning);
        }
    }
    ui_set_status(status);

    /* Combine headers + blank line + body into a single display
     * buffer and push it into the response pane. LF → CR conversion
     * because TERec uses CR as its line separator on classic Mac OS. */
    {
        static char display[32768];
        size_t dpos = 0;
        if (warning) {
            for (const char *w = warning; *w && dpos < sizeof(display); w++)
                display[dpos++] = *w;
            if (dpos + 2 < sizeof(display)) {
                display[dpos++] = '\r';
                display[dpos++] = '\r';
            }
        }
        for (size_t i = 0; i < headers_len && dpos < sizeof(display); i++) {
            char c = headers[i];
            if (c == '\n') c = '\r';
            display[dpos++] = c;
        }
        if (dpos + 1 < sizeof(display)) display[dpos++] = '\r';
        for (size_t i = 0; i < body_len && dpos < sizeof(display); i++) {
            char c = body[i];
            if (c == '\n') c = '\r';
            display[dpos++] = c;
        }
        ui_set_response(display, dpos);
    }

    finalize_send();
}

static void DoSendAndReceive(void)
{
    char url[1024];
    char headers[2048];
    char body[8192];
    char host[256];
    char path[1024];
    uint16_t port = 0;
    int url_len, headers_len, body_len;
    char status[256];

    /* Re-entrancy guard — ignore clicks while a send is active. */
    if (gSending) return;

    /* 1. Read editable fields into local buffers. */
    url_len = ui_get_url(url, sizeof(url));
    if (url_len < 0) {
        ui_set_status("URL too long");
        return;
    }
    headers_len = ui_get_headers(headers, sizeof(headers));
    if (headers_len < 0) {
        ui_set_status("Headers too long");
        return;
    }
    body_len = ui_get_body(body, sizeof(body));
    if (body_len < 0) {
        ui_set_status("Body too long");
        return;
    }

    /* 2. Parse the URL → host, port, path. */
    if (http_parse_url(url, (size_t)url_len,
                       host, sizeof(host), &port,
                       path, sizeof(path)) != 0) {
        ui_set_status("Bad URL (need https://host/path)");
        return;
    }

    /* 3. Build the full HTTP/1.1 request into gRequestBuf. */
    gRequestLen = http_build_request(
        ui_current_method(), host, path,
        headers, (size_t)headers_len,
        body,    (size_t)body_len,
        gRequestBuf, sizeof(gRequestBuf));
    if (gRequestLen < 0) {
        ui_set_status("Request too large");
        return;
    }

    /* 4. Reset response state and clear the response pane. */
    gResponseLen     = 0;
    gPrevResponseLen = 0;
    gRequestSent     = 0;
    gRequestIsHead   = strcmp(ui_current_method(), "HEAD") == 0;
    ui_clear_response();

    /* 5. Create the MacTLS context. */
    gCtx = MacTLS_Create(host, port);
    if (gCtx == NULL) {
        ui_set_status("TLS init failed: alloc");
        return;
    }
    if (MacTLS_GetState(gCtx) == kMacTLS_Error) {
        format_tls_error(status, sizeof(status));
        ui_set_status(status);
        MacTLS_Close(gCtx);
        gCtx = NULL;
        return;
    }

    /* Enter sending mode; the main loop will drive the handshake. */
    snprintf(status, sizeof(status),
             "Connecting to %s:%u...", host, (unsigned)port);
    ui_set_status(status);

    gSending   = 1;
    gCancelled = 0;
    ui_set_send_enabled(0);
}

static void on_send_click(void)
{
    DoSendAndReceive();
}

int main(void)
{
    EventRecord event;
    const char *seedError;

    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    InitOpenTransport();
    MacTLS_Init();
    seedError = SeedFromFile();

    ui_init();
    ui_set_send_handler(on_send_click);
    if (seedError != NULL) ui_set_status(seedError);

    while (!gQuit) {
        WaitNextEvent(everyEvent, &event, gSending ? 1 : 10, NULL);
        ui_handle_event(&event);
        if (gSending) DriveSendStep();
    }

    ui_dispose();
    MacTLS_Shutdown();
    CloseOpenTransport();
    return 0;
}
