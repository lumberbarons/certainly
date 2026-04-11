/*
 * simple_get.c — HTTPS GET against a variety of TLS 1.3 endpoints
 *
 * Iterates over a list of common HTTPS hosts, performs a GET /, and
 * records the outcome for each. Results are drawn in the window and
 * written to "The Outside World:certainly.log" (extfs) so they can be
 * inspected from the host without taking screenshots.
 *
 * Between each host we fully cycle Open Transport (Close/Init) and
 * wait a few ticks. Mac OS 9 OT can wedge if a previous async
 * connection failed mid-flight, so we give it a clean slate per test.
 */

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Menus.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Events.h>
#include <OpenTransport.h>
#include <Files.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "certainly.h"

/* ── Log file on extfs volume ── */
static short  gLogRefNum = 0;
static bool   gLogOpen   = false;

static void LogOpen(void)
{
    HParamBlockRec pb;
    Str255         name;
    OSErr          err;
    const char    *path = "The Outside World:certainly.log";
    size_t         len  = strlen(path);

    if (len > 255) len = 255;
    name[0] = (unsigned char)len;
    memcpy(&name[1], path, len);

    /* Wipe any previous log */
    memset(&pb, 0, sizeof(pb));
    pb.fileParam.ioNamePtr = name;
    PBHDeleteSync(&pb);

    memset(&pb, 0, sizeof(pb));
    pb.fileParam.ioNamePtr = name;
    err = PBHCreateSync(&pb);
    if (err != noErr && err != dupFNErr) return;

    memset(&pb, 0, sizeof(pb));
    pb.ioParam.ioNamePtr = name;
    pb.ioParam.ioPermssn = fsWrPerm;
    err = PBHOpenSync(&pb);
    if (err != noErr) return;

    gLogRefNum = pb.ioParam.ioRefNum;
    gLogOpen   = true;
}

static void LogLine(const char *text)
{
    long              len;
    static const char crlf[2] = {'\r', '\n'};

    if (!gLogOpen) return;
    len = (long)strlen(text);
    FSWrite(gLogRefNum, &len, text);
    len = 2;
    FSWrite(gLogRefNum, &len, crlf);
    /* Flush after every line so host can tail the log */
    FlushVol(NULL, 0);
}

static void LogClose(void)
{
    if (!gLogOpen) return;
    FSClose(gLogRefNum);
    FlushVol(NULL, 0);
    gLogOpen = false;
}

/* ── Status drawing ── */
static void DrawStatusLine(WindowPtr win, int line, const char *text)
{
    Rect   r;
    Str255 pstr;
    size_t len = strlen(text);

    if (len > 255) len = 255;
    pstr[0] = (unsigned char)len;
    memcpy(&pstr[1], text, len);

    r.top    = 20 + line * 14;
    r.bottom = r.top + 14;
    r.left   = 10;
    r.right  = 620;
    EraseRect(&r);
    MoveTo(12, r.bottom - 3);
    DrawString(pstr);
}

/* ── Test hosts ── */
typedef struct {
    const char *host;
    const char *note;
} TestHost;

static const TestHost kHosts[] = {
    { "raw.githubusercontent.com", "Fastly TLS 1.3"       },
    { "www.cloudflare.com",        "Cloudflare TLS 1.3"   },
    { "www.google.com",            "Google TLS 1.3"       },
    { "tls13.akamai.io",           "Akamai TLS 1.3 test"  },
    { "www.digicert.com",          "DigiCert TLS 1.3"     },
    { "httpbin.org",               "httpbin (maybe 1.2)"  },
};
#define kNumHosts (sizeof(kHosts) / sizeof(kHosts[0]))

/* Yield to the OS for `ticks` ticks while still pumping events. */
static void YieldTicks(uint32_t ticks)
{
    uint32_t end = (uint32_t)TickCount() + ticks;
    EventRecord ev;
    while ((uint32_t)TickCount() < end) {
        WaitNextEvent(everyEvent, &ev, 1, NULL);
    }
}

/*
 * Run a single endpoint test. Does its own InitOpenTransport /
 * CloseOpenTransport cycle so OT state is fresh for every host —
 * SheepShaver's OT emulation can wedge after a failed async op.
 */
static void TestOne(WindowPtr window, int line, const TestHost *t)
{
    MacTLS_Context *ctx;
    MacTLS_State    state, lastState = kMacTLS_Idle;
    EventRecord     event;
    char            request[512];
    char            response[4096];
    int             totalRead   = 0;
    bool            requestSent = false;
    bool            done        = false;
    char            status[256];
    char            statusLine[160];
    int             statusLen;
    uint32_t        startTicks;

    InitOpenTransport();

    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Certainly/0.1\r\n"
             "Connection: close\r\n"
             "\r\n",
             t->host);

    snprintf(status, sizeof(status), "[%s] connecting...", t->host);
    DrawStatusLine(window, line, status);

    ctx = MacTLS_Create(t->host, 443);
    if (ctx == NULL) {
        snprintf(status, sizeof(status), "[%s] FAIL: alloc", t->host);
        DrawStatusLine(window, line, status);
        LogLine(status);
        CloseOpenTransport();
        return;
    }

    if (MacTLS_GetState(ctx) == kMacTLS_Error) {
        snprintf(status, sizeof(status),
                 "[%s] FAIL(create): code=%d OT=%ld",
                 t->host,
                 MacTLS_GetError(ctx),
                 (long)MacTLS_GetOTError(ctx));
        DrawStatusLine(window, line, status);
        LogLine(status);
        MacTLS_Close(ctx);
        CloseOpenTransport();
        return;
    }

    startTicks = (uint32_t)TickCount();

    while (!done) {
        WaitNextEvent(everyEvent, &event, 1, NULL);

        /* 45 second per-host timeout */
        if ((uint32_t)TickCount() - startTicks > (45 * 60)) {
            snprintf(status, sizeof(status),
                     "[%s] FAIL: timeout in state %d",
                     t->host, (int)lastState);
            DrawStatusLine(window, line, status);
            LogLine(status);
            MacTLS_Close(ctx);
            CloseOpenTransport();
            return;
        }

        state = MacTLS_Pump(ctx);
        lastState = state;

        switch (state) {
        case kMacTLS_Connecting:
        case kMacTLS_Handshaking:
            break;

        case kMacTLS_Connected:
            if (!requestSent) {
                MacTLS_Write(ctx, request, strlen(request));
                requestSent = true;
            }
            {
                int n = MacTLS_Read(ctx, response + totalRead,
                                    sizeof(response) - totalRead - 1);
                if (n > 0) totalRead += n;
            }
            break;

        case kMacTLS_Closed:
            {
                int n;
                while ((n = MacTLS_Read(ctx, response + totalRead,
                                        sizeof(response) - totalRead - 1)) > 0) {
                    totalRead += n;
                }
            }
            response[totalRead] = '\0';

            {
                char *eol = strchr(response, '\r');
                if (eol) {
                    statusLen = (int)(eol - response);
                    if (statusLen > 140) statusLen = 140;
                    memcpy(statusLine, response, statusLen);
                    statusLine[statusLen] = '\0';
                } else {
                    strcpy(statusLine, "(no status line)");
                }
            }
            snprintf(status, sizeof(status),
                     "[%s] OK %dB %s",
                     t->host, totalRead, statusLine);
            DrawStatusLine(window, line, status);
            LogLine(status);
            done = true;
            break;

        case kMacTLS_Error:
            snprintf(status, sizeof(status),
                     "[%s] FAIL: code=%d OT=%ld bssl=%d (lastState=%d)",
                     t->host,
                     MacTLS_GetError(ctx),
                     (long)MacTLS_GetOTError(ctx),
                     MacTLS_GetBearSSLError(ctx),
                     (int)lastState);
            DrawStatusLine(window, line, status);
            LogLine(status);
            done = true;
            break;

        default:
            break;
        }
    }

    MacTLS_Close(ctx);
    /* Give OT notifier callbacks time to drain. */
    YieldTicks(60);
    CloseOpenTransport();
    YieldTicks(60);
}

int main(void)
{
    Rect        windowRect = {40, 10, 460, 680};
    WindowPtr   window;
    EventRecord event;
    size_t      i;
    char        header[128];

    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    MacTLS_Init();
    LogOpen();

    window = NewWindow(NULL, &windowRect,
                       "\pCertainly - Multi-endpoint TLS test",
                       true, documentProc, (WindowPtr)-1, false, 0);
    SetPort(window);

    snprintf(header, sizeof(header),
             "Testing %u endpoints...", (unsigned)kNumHosts);
    DrawStatusLine(window, 0, header);
    LogLine("=== Certainly multi-endpoint TLS test ===");
    LogLine(header);

    for (i = 0; i < kNumHosts; i++) {
        TestOne(window, (int)(i + 2), &kHosts[i]);
    }

    DrawStatusLine(window, (int)(kNumHosts + 3), "Done. Click to quit.");
    LogLine("=== Done ===");
    LogClose();

    do {
        WaitNextEvent(everyEvent, &event, 30, NULL);
    } while (event.what != mouseDown);

    MacTLS_Shutdown();
    DisposeWindow(window);
    return 0;
}
