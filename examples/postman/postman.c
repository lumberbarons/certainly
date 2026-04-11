/*
 * postman.c — Postman for Mac OS 9
 *
 * Interactive HTTPS tester built on the Certainly TLS library.
 * See docs/superpowers/specs/2026-04-11-postman-design.md for the design.
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

int gQuit = 0;

/* Send-flow state. Only postman.c touches these. */
static MacTLS_Context *gCtx              = NULL;
static int             gSending          = 0;
static int             gCancelled        = 0;
static int             gRequestSent      = 0;
static char            gRequestBuf[8192];
static int             gRequestLen       = 0;
static char            gResponseBuf[32768];
static int             gResponseLen      = 0;
static int             gPrevResponseLen  = 0;

/* ── Send flow ──────────────────────────────────────────────────── */

static void format_tls_error(char *out, size_t cap)
{
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
    gPrevResponseLen = 0;
    /* gResponseLen / gResponseBuf retained so the response pane
     * still reflects the last response until a new send starts. */
    ui_set_send_enabled(1);
}

static void finalize_response(int truncated);

static void DriveSendStep(void)
{
    MacTLS_State state;
    char         status[256];

    if (!gSending || !gCtx) return;

    /* Cancellation check — Task 16 wires Cmd-. to set gCancelled. */
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
            MacTLS_Write(gCtx, gRequestBuf, (size_t)gRequestLen);
            gRequestSent = 1;
            ui_set_status("Sending request...");
        }
        int space = (int)sizeof(gResponseBuf) - gResponseLen - 1;
        if (space <= 0) {
            /* Response buffer saturated — stop waiting for Close we
             * can't drain toward. Finalize with what we have. */
            finalize_response(1);
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
                         "Reading response (%d bytes)", gResponseLen);
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
        finalize_response(gResponseLen >= (int)sizeof(gResponseBuf) - 1);
        return;
    }

    case kMacTLS_Error:
        format_tls_error(status, sizeof(status));
        ui_set_status(status);
        finalize_send();
        return;

    default:
        break;
    }
}

static void finalize_response(int truncated)
{
    const char *status_line; size_t status_len;
    const char *headers;     size_t headers_len;
    const char *body;        size_t body_len;
    char        status[256];

    if (gResponseLen == 0) {
        ui_set_status("Empty response");
        finalize_send();
        return;
    }

    gResponseBuf[gResponseLen] = '\0';

    if (http_split_response(gResponseBuf, (size_t)gResponseLen,
                            &status_line, &status_len,
                            &headers,     &headers_len,
                            &body,        &body_len) != 0) {
        ui_set_status("Malformed HTTP response");
        /* Show raw first bytes so the user can see what came back. */
        int show = gResponseLen > 256 ? 256 : gResponseLen;
        ui_set_response(gResponseBuf, (size_t)show);
        finalize_send();
        return;
    }

    /* Build the status-line string, optionally suffixed with a
     * truncation note. */
    {
        size_t out_len = status_len;
        if (out_len > sizeof(status) - 32) out_len = sizeof(status) - 32;
        memcpy(status, status_line, out_len);
        status[out_len] = '\0';
        if (truncated) {
            strncat(status, "  (truncated to 32K)",
                    sizeof(status) - out_len - 1);
        }
    }
    ui_set_status(status);

    /* Combine headers + blank line + body into a single display
     * buffer and push it into the response pane. LF → CR conversion
     * because TERec uses CR as its line separator on classic Mac OS. */
    {
        static char display[32768];
        size_t dpos = 0;
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

    /* 6. Flip into sending mode. The main loop's next iteration
     *    will call DriveSendStep (Task 15) to pump the handshake. */
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

    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    InitOpenTransport();
    MacTLS_Init();

    ui_init();
    ui_set_send_handler(on_send_click);

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
