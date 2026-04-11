/*
 * ui.c — Window creation, drawing, focus, click/key dispatch.
 */

#include "ui.h"

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Controls.h>
#include <TextEdit.h>
#include <Menus.h>
#include <ToolUtils.h>
#include <string.h>

/* ── Layout constants ── */
enum {
    kWinLeft    = 40,
    kWinTop     = 40,
    kWinWidth   = 560,
    kWinHeight  = 400,

    kPad        = 10,          /* outer padding */
    kFieldH     = 20,          /* single-line field height */
    kRowGap     = 6,           /* vertical gap between rows */
    kLabelH     = 16,
    kMultiH     = 55,          /* multiline headers/body height */
    kResponseH  = 110,
    kButtonW    = 60,
    kScrollW    = 15
};

/* ── File-scope state ── */
static WindowPtr   gWindow       = NULL;

/* Rects computed at init time, referenced everywhere. */
static Rect        gMethodRect;      /* "Method: GET" clickable label */
static Rect        gURLLabelRect;    /* "URL:" static label */
static Rect        gURLRect;         /* URL edit field */
static Rect        gSendRect;        /* Send button */
static Rect        gHeadersLabelRect;
static Rect        gHeadersRect;
static Rect        gBodyLabelRect;
static Rect        gBodyRect;
static Rect        gStatusLabelRect;
static Rect        gStatusRect;      /* drawn status line (not a label) */
static Rect        gResponseLabelRect;
static Rect        gResponseRect;    /* includes scrollbar column */
static Rect        gResponseViewRect;/* minus scrollbar column */

/* ── Forward declarations ── */
static void ComputeLayout(void);
static void DrawChrome(void);

/* ── Public API ── */

void ui_init(void)
{
    Rect bounds;
    SetRect(&bounds, kWinLeft, kWinTop,
            kWinLeft + kWinWidth, kWinTop + kWinHeight);

    gWindow = NewCWindow(NULL, &bounds, "\pPostman",
                         true, documentProc,
                         (WindowPtr)-1L, false, 0);
    if (gWindow == NULL) return;
    SetPort(gWindow);
    TextFont(kFontIDGeneva);
    TextSize(10);

    ComputeLayout();
}

void ui_dispose(void)
{
    if (gWindow) {
        DisposeWindow(gWindow);
        gWindow = NULL;
    }
}

void ui_handle_event(const EventRecord *event)
{
    switch (event->what) {
    case updateEvt:
        if ((WindowPtr)event->message == gWindow) {
            SetPort(gWindow);
            BeginUpdate(gWindow);
            EraseRect(&gWindow->portRect);
            DrawChrome();
            EndUpdate(gWindow);
        }
        break;
    default:
        break;
    }
}

/* ── Layout ── */

static void ComputeLayout(void)
{
    /* Row 1: Method popup | URL label | URL field | Send button */
    short y = kPad;
    SetRect(&gMethodRect,
            kPad, y,
            kPad + 110, y + kFieldH);

    SetRect(&gURLLabelRect,
            gMethodRect.right + 8, y,
            gMethodRect.right + 8 + 30, y + kFieldH);

    short urlLeft  = gURLLabelRect.right + 4;
    short sendLeft = kWinWidth - kPad - kButtonW;
    SetRect(&gURLRect, urlLeft, y, sendLeft - 8, y + kFieldH);
    SetRect(&gSendRect, sendLeft, y, sendLeft + kButtonW, y + kFieldH);

    /* Row 2: "Headers:" label + multiline field */
    y += kFieldH + kRowGap;
    SetRect(&gHeadersLabelRect, kPad, y,
            kPad + 80, y + kLabelH);
    y += kLabelH;
    SetRect(&gHeadersRect, kPad, y,
            kWinWidth - kPad, y + kMultiH);

    /* Row 3: "Body:" label + multiline field */
    y += kMultiH + kRowGap;
    SetRect(&gBodyLabelRect, kPad, y,
            kPad + 80, y + kLabelH);
    y += kLabelH;
    SetRect(&gBodyRect, kPad, y,
            kWinWidth - kPad, y + kMultiH);

    /* Row 4: "Status:" label + drawn status line */
    y += kMultiH + kRowGap;
    SetRect(&gStatusLabelRect, kPad, y,
            kPad + 50, y + kLabelH);
    SetRect(&gStatusRect, kPad + 55, y,
            kWinWidth - kPad, y + kLabelH);

    /* Row 5: "Response:" label + response TE pane + scrollbar */
    y += kLabelH + kRowGap;
    SetRect(&gResponseLabelRect, kPad, y,
            kPad + 80, y + kLabelH);
    y += kLabelH;
    SetRect(&gResponseRect, kPad, y,
            kWinWidth - kPad, y + kResponseH);
    gResponseViewRect = gResponseRect;
    gResponseViewRect.right -= kScrollW;
}

/* ── Drawing ── */

static void DrawLabel(const Rect *r, const char *text)
{
    Str255 p;
    size_t len = strlen(text);
    if (len > 255) len = 255;
    p[0] = (unsigned char)len;
    memcpy(&p[1], text, len);

    MoveTo(r->left, r->bottom - 4);
    DrawString(p);
}

static void DrawChrome(void)
{
    /* Static labels. Method popup body is drawn by a later task; for
     * now just frame it and put "Method: GET" in its place as a placeholder. */
    FrameRect(&gMethodRect);
    {
        Rect inside = gMethodRect;
        InsetRect(&inside, 2, 0);
        MoveTo(inside.left + 2, inside.bottom - 5);
        DrawString("\pMethod: GET");
    }
    DrawLabel(&gURLLabelRect, "URL:");
    FrameRect(&gURLRect);

    FrameRect(&gSendRect);
    {
        Rect inside = gSendRect;
        short tw;
        MoveTo(0, 0);
        tw = StringWidth("\pSend");
        MoveTo(inside.left + (inside.right - inside.left - tw) / 2,
               inside.bottom - 6);
        DrawString("\pSend");
    }

    DrawLabel(&gHeadersLabelRect,  "Headers:");
    FrameRect(&gHeadersRect);

    DrawLabel(&gBodyLabelRect,     "Body:");
    FrameRect(&gBodyRect);

    DrawLabel(&gStatusLabelRect,   "Status:");
    /* Status text itself drawn blank for now. */

    DrawLabel(&gResponseLabelRect, "Response:");
    FrameRect(&gResponseRect);
}
