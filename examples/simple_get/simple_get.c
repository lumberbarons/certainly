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
#include <OpenTransport.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "certainly.h"

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

    const char *host = "httpbin.org";
    const char *request =
        "GET /get HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Accept: application/json\r\n"
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
    window = NewWindow(NULL, &windowRect, "\pCertainly — HTTPS GET",
                       true, documentProc, (WindowPtr)-1, false, 0);
    SetPort(window);

    DrawStatusLine(window, displayLine++,
                   "Connecting to httpbin.org:443...");

    /* Start TLS connection */
    ctx = MacTLS_Create(host, 443);
    if (ctx == NULL) {
        DrawStatusLine(window, displayLine++,
                       "ERROR: Failed to create context");
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
            /* TCP still connecting — just wait */
            break;

        case kMacTLS_Handshaking:
            DrawStatusLine(window, 1, "TLS handshake in progress...");
            break;

        case kMacTLS_Connected:
            if (!requestSent) {
                DrawStatusLine(window, 1, "TLS connected! Sending request...");
                MacTLS_Write(ctx, request, strlen(request));
                requestSent = true;
                displayLine = 3;
            }

            /* Try to read response data */
            {
                int n = MacTLS_Read(ctx, response + totalRead,
                                    sizeof(response) - totalRead - 1);
                if (n > 0) {
                    totalRead += n;
                    response[totalRead] = '\0';

                    /* Display response lines as they arrive */
                    DrawStatusLine(window, 2, "Receiving response...");
                }
            }
            break;

        case kMacTLS_Closed:
            /* Server closed connection — we're done */
            response[totalRead] = '\0';
            DrawStatusLine(window, 2, "Connection closed. Response:");

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
                sprintf(errMsg, "ERROR: code=%d, OT=%ld",
                        MacTLS_GetError(ctx),
                        (long)MacTLS_GetOTError(ctx));
                DrawStatusLine(window, displayLine++, errMsg);
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
