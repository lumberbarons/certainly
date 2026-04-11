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
        WaitNextEvent(everyEvent, &event, 10, NULL);
        ui_handle_event(&event);
    }

    ui_dispose();
    MacTLS_Shutdown();
    CloseOpenTransport();
    return 0;
}
