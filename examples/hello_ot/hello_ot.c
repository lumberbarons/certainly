/*
 * hello_ot.c — Test Open Transport TCP connectivity
 *
 * Connects to http://example.com:80 (plain HTTP, no TLS) and
 * sends a GET request. Displays the response in a window.
 *
 * This proves:
 *   1. OT initializes correctly
 *   2. DNS resolution works
 *   3. TCP connect works
 *   4. Send/receive works
 *   5. The async pump loop works with WaitNextEvent
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

#include "ot_transport.h"

static void DrawStatus(WindowPtr win, const char *status)
{
    Rect r = {140, 10, 160, 390};
    EraseRect(&r);
    MoveTo(20, 155);
    {
        Str255 pstr;
        size_t len = strlen(status);
        if (len > 255) len = 255;
        pstr[0] = (unsigned char)len;
        memcpy(&pstr[1], status, len);
        DrawString(pstr);
    }
}

int main(void)
{
    Rect          windowRect = {40, 40, 300, 420};
    WindowPtr     window;
    EventRecord   event;
    OTTransport  *transport;
    char          response[512];
    int           totalRead = 0;
    bool          requestSent = false;
    bool          done = false;

    const char *httpReq =
        "GET / HTTP/1.0\r\n"
        "Host: example.com\r\n"
        "\r\n";

    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    /* Initialize Open Transport — must do this before any OT calls */
    InitOpenTransportInContext(kInitOTForApplicationMask, NULL);

    window = NewWindow(NULL, &windowRect, "\pOT Test", true,
                       documentProc, (WindowPtr)-1, false, 0);
    SetPort(window);
    MoveTo(20, 30);
    DrawString("\pConnecting to example.com:80...");

    transport = ot_transport_create("example.com", 80);
    if (transport == NULL) {
        DrawStatus(window, "Failed to create transport");
        goto wait_quit;
    }

    while (!done) {
        WaitNextEvent(everyEvent, &event, 1, NULL);
        if (event.what == mouseDown) { done = true; break; }

        switch (ot_transport_pump(transport)) {
        case kOTTransport_ResolvingDNS:
            DrawStatus(window, "Resolving DNS...");
            break;

        case kOTTransport_Connecting:
            DrawStatus(window, "TCP connecting...");
            break;

        case kOTTransport_Connected:
            if (!requestSent) {
                DrawStatus(window, "Connected! Sending request...");
                ot_transport_send(transport, httpReq, strlen(httpReq));
                requestSent = true;
            } else {
                int n = ot_transport_recv(transport, response + totalRead,
                                          sizeof(response) - totalRead - 1);
                if (n > 0) {
                    totalRead += n;
                    response[totalRead] = '\0';
                    DrawStatus(window, "Receiving data...");
                }
            }
            break;

        case kOTTransport_Closed:
            response[totalRead] = '\0';
            DrawStatus(window, response);
            done = true;
            break;

        case kOTTransport_Error:
            DrawStatus(window, "Connection error!");
            done = true;
            break;

        default:
            break;
        }
    }

wait_quit:
    MoveTo(20, 280);
    DrawString("\pClick to quit.");
    do {
        WaitNextEvent(everyEvent, &event, 30, NULL);
    } while (event.what != mouseDown);

    ot_transport_destroy(transport);
    CloseOpenTransportInContext();
    DisposeWindow(window);
    return 0;
}
