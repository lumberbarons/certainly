/*
 * simple_get.c — HTTPS GET request using Certainly
 *
 * This is the "hello world" of TLS — connect to a server over
 * HTTPS, send a GET request, and display the response.
 *
 * We use httpbin.org which returns JSON describing the request.
 * If this works, you have a working TLS 1.2 stack on Mac OS 9.
 */

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Menus.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Events.h>
#include <Files.h>
#include <OpenTransport.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "certainly.h"

/*
 * Log to a file on the extfs-mapped "Unix" volume.
 * The host has /tmp/ss_log mapped as a Mac OS 9 volume named "Unix".
 * We append to "Unix:certainly.log" which shows up on the host at
 * /tmp/ss_log/certainly.log — we can tail -f it from the Mac.
 */
static void log_line(const char *msg)
{
    FSSpec spec;
    short ref;
    OSErr err;
    long len;
    char newline = '\n';

    /* Find the Unix volume by name */
    err = FSMakeFSSpec(0, 0, "\pThe Outside World:certainly.log", &spec);
    if (err == fnfErr) {
        /* File doesn't exist — create it */
        FSpCreate(&spec, 'ttxt', 'TEXT', smSystemScript);
    } else if (err != noErr) {
        return;  /* Can't even find the volume */
    }

    if (FSpOpenDF(&spec, fsWrPerm, &ref) != noErr) return;

    /* Seek to end, append line + newline */
    SetFPos(ref, fsFromLEOF, 0);
    len = strlen(msg);
    FSWrite(ref, &len, msg);
    len = 1;
    FSWrite(ref, &len, &newline);
    FSClose(ref);  /* flush */
}

/* Display status text in the window */
static void DrawStatusLine(WindowPtr win, int line, const char *text)
{
    Rect  r;
    Str255 pstr;
    size_t len = strlen(text);

    if (len > 255) len = 255;
    pstr[0] = (unsigned char)len;
    memcpy(&pstr[1], text, len);

    r.top    = 20 + line * 16;
    r.bottom = r.top + 16;
    r.left   = 10;
    r.right  = 590;
    EraseRect(&r);
    MoveTo(12, r.bottom - 3);
    DrawString(pstr);
}

int main(void)
{
    Rect            windowRect = {40, 10, 440, 600};
    WindowPtr       window;
    EventRecord     event;
    MacTLS_Context *ctx;
    MacTLS_State    state;
    char            response[4096];
    int             totalRead = 0;
    bool            requestSent = false;
    bool            done = false;
    int             displayLine = 0;

    const char *host = "raw.githubusercontent.com";
    const char *request =
        "GET /anthropics/claude-code/main/README.md HTTP/1.1\r\n"
        "Host: raw.githubusercontent.com\r\n"
        "User-Agent: Certainly/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";

    /* Standard Toolbox init */
    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    /* Initialize Open Transport */
    InitOpenTransport();

    /* Initialize Certainly */
    MacTLS_Init();

    /* Create window */
    window = NewWindow(NULL, &windowRect, "\pCertainly - HTTPS GET",
                       true, documentProc, (WindowPtr)-1, false, 0);
    SetPort(window);

    DrawStatusLine(window, displayLine++,
                   "Connecting to tls13.akamai.io:443...");

    /* Start TLS connection */
    ctx = MacTLS_Create(host, 443);
    if (ctx == NULL) {
        DrawStatusLine(window, displayLine++,
                       "ERROR: Failed to create context (NULL)");
        goto wait_quit;
    }

    {
        char dbg[128];
        sprintf(dbg, "Created ctx, state=%d err=%d OT=%ld",
                MacTLS_GetState(ctx), MacTLS_GetError(ctx),
                (long)MacTLS_GetOTError(ctx));
        DrawStatusLine(window, displayLine++, dbg);
    }

    if (MacTLS_GetState(ctx) == kMacTLS_Error) {
        char errMsg[128];
        sprintf(errMsg, "Create failed: code=%d, OT=%ld",
                MacTLS_GetError(ctx), (long)MacTLS_GetOTError(ctx));
        DrawStatusLine(window, displayLine++, errMsg);
        goto wait_quit;
    }

    /* Main event loop */
    while (!done) {
        WaitNextEvent(everyEvent, &event, 1, NULL);
        if (event.what == mouseDown) {
            /* Check if click is in our window — if so, quit */
            WindowPtr clickWin;
            if (FindWindow(event.where, &clickWin) == inContent) {
                done = true;
                break;
            }
        }

        /* Pump the TLS connection */
        state = MacTLS_Pump(ctx);

        switch (state) {
        case kMacTLS_Connecting:
            DrawStatusLine(window, 2, "TCP connecting (DNS/connect)...");
            break;

        case kMacTLS_Handshaking:
            DrawStatusLine(window, 1, "TLS handshake in progress...");
            break;

        case kMacTLS_Connected:
            if (!requestSent) {
                char logbuf[200];
                DrawStatusLine(window, 1, "TLS connected! Sending request...");
                log_line("=== State: Connected ===");
                sprintf(logbuf, "sent=%lu recv=%lu rrlen@conn=%lu",
                        (unsigned long)MacTLS_GetDbgTotalSent(ctx),
                        (unsigned long)MacTLS_GetDbgTotalRecv(ctx),
                        (unsigned long)MacTLS_GetDbgRecvLenAtConnected(ctx));
                log_line(logbuf);
                log_line("About to send HTTP request");
                MacTLS_Write(ctx, request, strlen(request));
                log_line("HTTP request sent");
                requestSent = true;
                displayLine = 3;
            }

            /* Try to read response data */
            {
                int n = MacTLS_Read(ctx, response + totalRead,
                                    sizeof(response) - totalRead - 1);
                if (n > 0) {
                    char logbuf[80];
                    totalRead += n;
                    response[totalRead] = '\0';
                    sprintf(logbuf, "Read %d bytes, total=%d", n, totalRead);
                    log_line(logbuf);
                    /* Display response lines as they arrive */
                    DrawStatusLine(window, 2, "Receiving response...");
                }
            }
            break;

        case kMacTLS_Closed:
            /* Server closed connection — drain any remaining response data */
            log_line("=== State: Closed ===");
            {
                int n;
                while ((n = MacTLS_Read(ctx, response + totalRead,
                                        sizeof(response) - totalRead - 1)) > 0) {
                    totalRead += n;
                }
            }
            response[totalRead] = '\0';
            {
                char dbgmsg[128];
                sprintf(dbgmsg, "Closed total=%d sent=%lu recv=%lu",
                        totalRead,
                        (unsigned long)MacTLS_GetDbgTotalSent(ctx),
                        (unsigned long)MacTLS_GetDbgTotalRecv(ctx));
                DrawStatusLine(window, 2, dbgmsg);
                log_line(dbgmsg);
                sprintf(dbgmsg, "post=%d app=%d hs=%d alrt=%d maxApp=%lu",
                        MacTLS_GetDbgPostRecords(ctx),
                        MacTLS_GetDbgAppRecords(ctx),
                        MacTLS_GetDbgHsRecords(ctx),
                        MacTLS_GetDbgAlertRecords(ctx),
                        (unsigned long)MacTLS_GetDbgMaxAppLen(ctx));
                log_line(dbgmsg);
                sprintf(dbgmsg, "write=%d/%lu rrcalls=%d decFail=%d lastCT=%d",
                        MacTLS_GetDbgWriteCalls(ctx),
                        (unsigned long)MacTLS_GetDbgWriteBytes(ctx),
                        MacTLS_GetDbgRecvRecordsCalls(ctx),
                        MacTLS_GetDbgDecryptFailures(ctx),
                        MacTLS_GetDbgLastInnerCt(ctx));
                log_line(dbgmsg);
                sprintf(dbgmsg, "build_ch=%d build_finished=%d hs_step=%d",
                        MacTLS_GetDbgBuildChCalls(ctx),
                        MacTLS_GetDbgBuildFinishedCalls(ctx),
                        MacTLS_GetDbgHandshakeStepCalls(ctx));
                log_line(dbgmsg);
                sprintf(dbgmsg, "send_block_enters=%d max_msg_len=%lu",
                        MacTLS_GetDbgSendBlockEnters(ctx),
                        (unsigned long)MacTLS_GetDbgSendBlockMaxMsgLen(ctx));
                log_line(dbgmsg);
                /* Log recv_buf contents */
                {
                    const unsigned char *rb = MacTLS_GetTLS13RecvBuf(ctx);
                    size_t rl = MacTLS_GetTLS13RecvLen(ctx);
                    size_t i, limit = rl > 32 ? 32 : rl;
                    char hex[200];
                    char *p = hex;
                    sprintf(p, "recvbuf[%lu]: ", (unsigned long)rl);
                    p += strlen(p);
                    for (i = 0; i < limit; i++) {
                        sprintf(p, "%02x ", rb[i]);
                        p += 3;
                    }
                    *p = '\0';
                    log_line(hex);
                }
                /* Log the response if we got one */
                if (totalRead > 0) {
                    log_line("--- Response body ---");
                    log_line(response);
                    log_line("--- End response ---");
                } else {
                    log_line("NO RESPONSE BODY RECEIVED");
                }
                sprintf(dbgmsg, "post=%d app=%d alrt=%d lastCT=%d",
                        MacTLS_GetDbgPostRecords(ctx),
                        MacTLS_GetDbgAppRecords(ctx),
                        MacTLS_GetDbgAlertRecords(ctx),
                        MacTLS_GetDbgLastInnerCt(ctx));
                DrawStatusLine(window, 5, dbgmsg);
                sprintf(dbgmsg, "post=%d app=%d alrt=%d lastCT=%d",
                        MacTLS_GetDbgPostRecords(ctx),
                        MacTLS_GetDbgAppRecords(ctx),
                        MacTLS_GetDbgAlertRecords(ctx),
                        MacTLS_GetDbgLastInnerCt(ctx));
                DrawStatusLine(window, 5, dbgmsg);
                sprintf(dbgmsg, "write=%d/%lu rrcalls=%d rrlen@conn=%lu decFail=%d",
                        MacTLS_GetDbgWriteCalls(ctx),
                        (unsigned long)MacTLS_GetDbgWriteBytes(ctx),
                        MacTLS_GetDbgRecvRecordsCalls(ctx),
                        (unsigned long)MacTLS_GetDbgRecvLenAtConnected(ctx),
                        MacTLS_GetDbgDecryptFailures(ctx));
                DrawStatusLine(window, 6, dbgmsg);
                sprintf(dbgmsg, "recv=%lu plain=%lu/%lu hs13err=%d",
                        (unsigned long)MacTLS_GetTLS13RecvLen(ctx),
                        (unsigned long)MacTLS_GetDbgPlainOffset(ctx),
                        (unsigned long)MacTLS_GetDbgPlainLen(ctx),
                        MacTLS_GetTLS13Error(ctx));
                DrawStatusLine(window, 3, dbgmsg);
                /* Dump first bytes of recv_buf */
                {
                    const unsigned char *rb = MacTLS_GetTLS13RecvBuf(ctx);
                    size_t rl = MacTLS_GetTLS13RecvLen(ctx);
                    size_t i, limit = rl > 16 ? 16 : rl;
                    char hex[128];
                    char *p = hex;
                    for (i = 0; i < limit; i++) {
                        sprintf(p, "%02x ", rb[i]);
                        p += 3;
                    }
                    *p = '\0';
                    sprintf(dbgmsg, "recvbuf: %s", hex);
                    DrawStatusLine(window, 4, dbgmsg);
                }
            }

            /* Display the response, line by line */
            {
                char *line = response;
                char *next;
                displayLine = 3;

                while ((next = strchr(line, '\n')) != NULL
                       && displayLine < 24) {
                    *next = '\0';
                    DrawStatusLine(window, displayLine++, line);
                    line = next + 1;
                }
                if (*line && displayLine < 24) {
                    DrawStatusLine(window, displayLine++, line);
                }
            }
            done = true;
            break;

        case kMacTLS_Error:
            {
                char errMsg[128];
                sprintf(errMsg, "ERROR: code=%d OT=%ld BSSL=%d",
                        MacTLS_GetError(ctx),
                        (long)MacTLS_GetOTError(ctx),
                        MacTLS_GetBearSSLError(ctx));
                DrawStatusLine(window, displayLine++, errMsg);
                sprintf(errMsg, "tls13: state=%d err=%d msg=%lu/%lu recv=%lu",
                        MacTLS_GetTLS13State(ctx),
                        MacTLS_GetTLS13Error(ctx),
                        (unsigned long)MacTLS_GetTLS13MsgOffset(ctx),
                        (unsigned long)MacTLS_GetTLS13MsgLen(ctx),
                        (unsigned long)MacTLS_GetTLS13RecvLen(ctx));
                DrawStatusLine(window, displayLine++, errMsg);
                /* Dump first bytes of recv buffer in hex */
                {
                    const unsigned char *rb = MacTLS_GetTLS13RecvBuf(ctx);
                    size_t rl = MacTLS_GetTLS13RecvLen(ctx);
                    size_t i;
                    char hex[128];
                    char *p = hex;
                    size_t limit = rl > 16 ? 16 : rl;
                    for (i = 0; i < limit; i++) {
                        sprintf(p, "%02x ", rb[i]);
                        p += 3;
                    }
                    *p = '\0';
                    sprintf(errMsg, "recv: %s", hex);
                    DrawStatusLine(window, displayLine++, errMsg);
                }
                sprintf(errMsg, "dbg: pumps=%lu sent=%lu recv=%lu",
                        (unsigned long)MacTLS_GetDbgPumpCount(ctx),
                        (unsigned long)MacTLS_GetDbgTotalSent(ctx),
                        (unsigned long)MacTLS_GetDbgTotalRecv(ctx));
                DrawStatusLine(window, displayLine++, errMsg);
                /* First 16 bytes of ClientHello (as sent) */
                {
                    const unsigned char *sb = MacTLS_GetDbgFirstSend(ctx);
                    size_t i;
                    char hex[128];
                    char *p = hex;
                    for (i = 0; i < 16; i++) {
                        sprintf(p, "%02x ", sb[i]);
                        p += 3;
                    }
                    *p = '\0';
                    sprintf(errMsg, "sent: %s", hex);
                    DrawStatusLine(window, displayLine++, errMsg);
                }
            }
            done = true;
            break;

        default:
            break;
        }
    }

wait_quit:
    DrawStatusLine(window, 25, "Click to quit.");
    do {
        WaitNextEvent(everyEvent, &event, 30, NULL);
    } while (event.what != mouseDown);

    /* Cleanup */
    if (ctx) MacTLS_Close(ctx);
    MacTLS_Shutdown();
    CloseOpenTransport();
    DisposeWindow(window);
    return 0;
}
