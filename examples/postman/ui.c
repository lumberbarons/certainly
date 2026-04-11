/*
 * ui.c — Window creation, drawing, focus, click/key dispatch.
 */

#include "ui.h"

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Controls.h>
#include <ControlDefinitions.h>
#include <TextEdit.h>
#include <Menus.h>
#include <ToolUtils.h>
#include <string.h>

/* ── Layout constants ── */
enum {
    kWinLeft    = 40,
    kWinTop     = 40,
    kWinWidth   = 600,
    kWinHeight  = 400,

    kPad        = 10,          /* outer padding */
    kFieldH     = 20,          /* single-line field height */
    kRowGap     = 6,           /* vertical gap between rows */
    kLabelH     = 16,
    kMultiH     = 55,          /* headers field height */
    kBodyH      = 85,          /* body field height */
    kResponseH  = 95,
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

static TEHandle    gURLTE           = NULL;
static TEHandle    gHeadersTE       = NULL;
static TEHandle    gBodyTE          = NULL;
static TEHandle    gFocusedTE       = NULL;

static ControlHandle gSendBtn        = NULL;
static SendHandler   gSendHandler    = NULL;

static MenuHandle gAppleMenu    = NULL;
static MenuHandle gFileMenu     = NULL;
static MenuHandle gEditMenu     = NULL;

static MenuHandle  gMethodMenu      = NULL;
static short       gMethodIndex     = 1;  /* 1 = GET */
static const char *kMethodNames[5] = { NULL, "GET", "POST", "PUT", "DELETE" };

static TEHandle          gResponseTE      = NULL;
static ControlHandle     gResponseScroll  = NULL;
static ControlActionUPP  gScrollActionUPP = NULL;

static char gStatusText[256] = "(no request sent)";

/* ── Forward declarations ── */
static void ComputeLayout(void);
static void DrawChrome(void);
static pascal void ScrollActionProc(ControlHandle c, short part);

static void focus_set(TEHandle te)
{
    if (gFocusedTE == te) return;
    if (gFocusedTE) TEDeactivate(gFocusedTE);
    gFocusedTE = te;
    if (gFocusedTE) TEActivate(gFocusedTE);
}

static void focus_advance(int backward)
{
    TEHandle ring[3] = { gURLTE, gHeadersTE, gBodyTE };
    int cur = -1;
    for (int i = 0; i < 3; i++) {
        if (ring[i] == gFocusedTE) { cur = i; break; }
    }
    if (cur < 0) cur = 0;
    int next = backward ? (cur + 2) % 3 : (cur + 1) % 3;
    focus_set(ring[next]);
}

/* ── Public API ── */

void ui_init(void)
{
    gAppleMenu = GetMenu(129);
    if (gAppleMenu) {
        AppendResMenu(gAppleMenu, 'DRVR');  /* DA list on the Apple menu */
        InsertMenu(gAppleMenu, 0);
    }
    gFileMenu = GetMenu(130);
    if (gFileMenu) InsertMenu(gFileMenu, 0);
    gEditMenu = GetMenu(131);
    if (gEditMenu) InsertMenu(gEditMenu, 0);
    DrawMenuBar();

    /* Method popup — hierarchical (not in the menu bar), used as a
     * popup triggered by clicks on gMethodRect. */
    gMethodMenu = GetMenu(128);
    if (gMethodMenu == NULL) {
        /* Method menu resource missing — app cannot sensibly run. */
        ExitToShell();
    }
    InsertMenu(gMethodMenu, -1);

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

    gSendBtn = NewControl(gWindow, &gSendRect, "\pSend",
                          true, 0, 0, 1, pushButProc, 0);

    /* URL field — single-line. destRect can extend horizontally
     * beyond viewRect to allow horizontal scrolling via arrow keys. */
    {
        Rect view = gURLRect;
        InsetRect(&view, 3, 2);
        Rect dest = view;
        dest.right += 4000;   /* allow long URLs */
        gURLTE = TENew(&dest, &view);
    }

    /* Headers field — multiline. */
    {
        Rect view = gHeadersRect;
        InsetRect(&view, 3, 2);
        Rect dest = view;
        gHeadersTE = TENew(&dest, &view);
    }

    /* Body field — multiline. */
    {
        Rect view = gBodyRect;
        InsetRect(&view, 3, 2);
        Rect dest = view;
        gBodyTE = TENew(&dest, &view);
    }

    /* Install default text. TERec uses CR (\r) as its line separator,
     * not LF (\n). The defaults below give the user a runnable demo
     * against the Anthropic Messages API — paste a real key into the
     * x-api-key header and hit Send. */
    if (gURLTE) {
        const char *url = "https://api.anthropic.com/v1/messages";
        TESetText(url, (long)strlen(url), gURLTE);
    }
    if (gHeadersTE) {
        const char *hdefs =
            "x-api-key: YOUR_API_KEY_HERE\r"
            "anthropic-version: 2023-06-01\r"
            "content-type: application/json";
        TESetText(hdefs, (long)strlen(hdefs), gHeadersTE);
    }
    if (gBodyTE) {
        const char *bdefs =
            "{\r"
            "  \"model\": \"claude-haiku-4-5\",\r"
            "  \"max_tokens\": 256,\r"
            "  \"messages\": [\r"
            "    {\"role\": \"user\",\r"
            "     \"content\": \"Write a haiku about Claude running on a classic Mac in 2026.\"}\r"
            "  ]\r"
            "}";
        TESetText(bdefs, (long)strlen(bdefs), gBodyTE);
    }

    /* Enable auto-scroll: when the caret moves off-screen via typing or
     * arrow keys, TESelView (called from the keyDown handler below and
     * from TEClick's default click loop) will pan destRect so the caret
     * stays visible. destRect is "bottomless" per Inside Macintosh Text
     * p. 2-28, so no need to pre-size it taller than viewRect. */
    if (gURLTE)     TEAutoView(true, gURLTE);
    if (gHeadersTE) TEAutoView(true, gHeadersTE);
    if (gBodyTE)    TEAutoView(true, gBodyTE);

    /* Response pane: TE inside the response viewRect, scrollbar
     * in the rightmost 15-pixel column of gResponseRect. */
    {
        Rect view = gResponseViewRect;
        InsetRect(&view, 3, 2);
        Rect dest = view;
        gResponseTE = TENew(&dest, &view);
    }

    {
        Rect sb;
        sb.top    = gResponseRect.top;
        sb.bottom = gResponseRect.bottom;
        sb.right  = gResponseRect.right + 1;
        sb.left   = sb.right - (15 + 1);
        gResponseScroll = NewControl(gWindow, &sb, "\p",
                                     true, 0, 0, 0,
                                     scrollBarProc, 0);
    }

    gScrollActionUPP = NewControlActionUPP(ScrollActionProc);

    focus_set(gURLTE);
}

void ui_dispose(void)
{
    if (gBodyTE)    { TEDispose(gBodyTE);    gBodyTE    = NULL; }
    if (gHeadersTE) { TEDispose(gHeadersTE); gHeadersTE = NULL; }
    if (gURLTE)     { TEDispose(gURLTE);     gURLTE     = NULL; }

    if (gSendBtn) { DisposeControl(gSendBtn); gSendBtn = NULL; }

    if (gResponseScroll) {
        DisposeControl(gResponseScroll);
        gResponseScroll = NULL;
    }
    if (gResponseTE) { TEDispose(gResponseTE); gResponseTE = NULL; }
    if (gScrollActionUPP) {
        DisposeControlActionUPP(gScrollActionUPP);
        gScrollActionUPP = NULL;
    }

    if (gEditMenu)  { DeleteMenu(131); DisposeMenu(gEditMenu);  gEditMenu  = NULL; }
    if (gFileMenu)  { DeleteMenu(130); DisposeMenu(gFileMenu);  gFileMenu  = NULL; }
    if (gAppleMenu) { DeleteMenu(129); DisposeMenu(gAppleMenu); gAppleMenu = NULL; }

    if (gMethodMenu) {
        DeleteMenu(128);
        DisposeMenu(gMethodMenu);
        gMethodMenu = NULL;
    }

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

    case mouseDown: {
        WindowPtr which;
        short part = FindWindow(event->where, &which);
        if (part == inMenuBar) {
            long choice = MenuSelect(event->where);
            if (ui_handle_menu(choice)) {
                extern int gQuit;
                gQuit = 1;
            }
            HiliteMenu(0);
            break;
        }
        if (which != gWindow) break;

        if (part == inDrag) {
            Rect screen = (*GetGrayRgn())->rgnBBox;
            DragWindow(gWindow, event->where, &screen);
            break;
        }
        if (part != inContent) break;

        SetPort(gWindow);
        Point local = event->where;
        GlobalToLocal(&local);

        /* Method popup — click anywhere in gMethodRect opens a
         * standard Mac OS 9 popup menu at the rect's bottom-left. */
        if (PtInRect(local, &gMethodRect)) {
            Point anchor;
            anchor.v = gMethodRect.bottom;
            anchor.h = gMethodRect.left;
            LocalToGlobal(&anchor);

            long chosen = PopUpMenuSelect(gMethodMenu,
                                          anchor.v, anchor.h,
                                          gMethodIndex);
            short item = LoWord(chosen);
            if (item >= 1 && item <= 4) {
                gMethodIndex = item;
                InvalRect(&gMethodRect);
            }
            break;
        }

        /* Send button (real ControlHandle — check first so the
         * button grabs the click before any TE field hit-test). */
        if (gSendBtn) {
            ControlHandle ctl = NULL;
            short cpart = FindControl(local, gWindow, &ctl);
            if (cpart && ctl == gSendBtn) {
                if (TrackControl(ctl, local, NULL) == kControlButtonPart &&
                    gSendHandler) {
                    gSendHandler();
                }
                break;
            }
        }

        /* Response pane scrollbar */
        if (gResponseScroll) {
            ControlHandle ctl = NULL;
            short cpart = FindControl(local, gWindow, &ctl);
            if (cpart && ctl == gResponseScroll) {
                if (cpart == kControlIndicatorPart) {
                    /* Direct thumb drag — action proc is not called
                     * during indicator tracking, so reconcile
                     * afterward by reading the control value and
                     * calling TEScroll to match. */
                    short before = GetControlValue(ctl);
                    TrackControl(ctl, local, NULL);
                    short after = GetControlValue(ctl);
                    if (after != before && gResponseTE) {
                        TEScroll(0, (short)(before - after), gResponseTE);
                    }
                } else {
                    /* Arrow or page part — action proc handles each
                     * tick. */
                    TrackControl(ctl, local, gScrollActionUPP);
                }
                break;
            }
        }

        if (gURLTE && PtInRect(local, &(*gURLTE)->viewRect)) {
            focus_set(gURLTE);
            TEClick(local, (event->modifiers & shiftKey) != 0, gURLTE);
        } else if (gHeadersTE && PtInRect(local, &(*gHeadersTE)->viewRect)) {
            focus_set(gHeadersTE);
            TEClick(local, (event->modifiers & shiftKey) != 0, gHeadersTE);
        } else if (gBodyTE && PtInRect(local, &(*gBodyTE)->viewRect)) {
            focus_set(gBodyTE);
            TEClick(local, (event->modifiers & shiftKey) != 0, gBodyTE);
        }
        break;
    }

    case keyDown:
    case autoKey: {
        char c = (char)(event->message & charCodeMask);
        if (event->modifiers & cmdKey) {
            long choice = MenuKey(c);
            if (HiWord(choice) != 0) {
                if (ui_handle_menu(choice)) {
                    extern int gQuit;
                    gQuit = 1;
                }
                HiliteMenu(0);
                break;
            }
            /* Unhandled cmd-key — fall through to TEKey so Cmd-arrow
             * and friends work inside TE fields. */
        }
        if (c == 0x09) { /* Tab */
            focus_advance((event->modifiers & shiftKey) != 0);
            break;
        }
        if (gFocusedTE) {
            TEKey(c, gFocusedTE);
            TESelView(gFocusedTE);  /* keep caret visible */
        }
        break;
    }

    case activateEvt: {
        int active = (event->modifiers & activeFlag) != 0;
        if (gFocusedTE) {
            if (active) TEActivate(gFocusedTE);
            else        TEDeactivate(gFocusedTE);
        }
        break;
    }

    default:
        break;
    }

    if (gFocusedTE) TEIdle(gFocusedTE);
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
            kWinWidth - kPad, y + kBodyH);

    /* Row 4: "Status:" label + drawn status line */
    y += kBodyH + kRowGap;
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

static void DrawStatus(void)
{
    EraseRect(&gStatusRect);
    Str255 p;
    size_t n = strlen(gStatusText);
    if (n > 255) n = 255;
    p[0] = (unsigned char)n;
    memcpy(&p[1], gStatusText, n);
    MoveTo(gStatusRect.left, gStatusRect.bottom - 4);
    DrawString(p);
}

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
    FrameRect(&gMethodRect);
    {
        Str255 label;
        const char *name = kMethodNames[gMethodIndex];
        size_t nlen = strlen(name);
        if (nlen > 247) nlen = 247;   /* leave room for "Method: " */
        /* Build "Method: NAME" as a Pascal string. */
        label[0] = (unsigned char)(8 + nlen);
        memcpy(&label[1], "Method: ", 8);
        memcpy(&label[1 + 8], name, nlen);

        MoveTo(gMethodRect.left + 4, gMethodRect.bottom - 5);
        DrawString(label);

        /* Draw a small 'v' on the right as a cheap disclosure hint. */
        MoveTo(gMethodRect.right - 10, gMethodRect.bottom - 7);
        DrawChar('v');
    }
    DrawLabel(&gURLLabelRect, "URL:");
    FrameRect(&gURLRect);

    DrawLabel(&gHeadersLabelRect,  "Headers:");
    FrameRect(&gHeadersRect);

    DrawLabel(&gBodyLabelRect,     "Body:");
    FrameRect(&gBodyRect);

    if (gURLTE)     TEUpdate(&(*gURLTE)->viewRect,     gURLTE);
    if (gHeadersTE) TEUpdate(&(*gHeadersTE)->viewRect, gHeadersTE);
    if (gBodyTE)    TEUpdate(&(*gBodyTE)->viewRect,    gBodyTE);

    DrawLabel(&gStatusLabelRect,   "Status:");
    DrawStatus();

    DrawLabel(&gResponseLabelRect, "Response:");
    FrameRect(&gResponseRect);
    if (gResponseTE) TEUpdate(&(*gResponseTE)->viewRect, gResponseTE);

    DrawControls(gWindow);
}

/* ── Response pane helpers and scroll action proc ── */

static short ResponseLineHeight(void)
{
    if (!gResponseTE) return 12;
    short lh = (*gResponseTE)->lineHeight;
    return lh > 0 ? lh : 12;
}

static short ResponsePageHeight(void)
{
    if (!gResponseTE) return 12;
    Rect v = (*gResponseTE)->viewRect;
    short lh = ResponseLineHeight();
    short visible_lines = (v.bottom - v.top) / lh;
    /* Page scroll moves visible_lines - 1 to keep one line of context. */
    return (visible_lines > 1) ? (short)((visible_lines - 1) * lh) : lh;
}

static short ClampScroll(short v)
{
    if (!gResponseScroll) return 0;
    short max = GetControlMaximum(gResponseScroll);
    if (v < 0)  v = 0;
    if (v > max) v = max;
    return v;
}

static short ComputeMaxScroll(void)
{
    if (!gResponseTE) return 0;
    short lh = ResponseLineHeight();
    short nLines = (*gResponseTE)->nLines;
    Rect  view   = (*gResponseTE)->viewRect;
    short visible_lines = (view.bottom - view.top) / lh;
    short excess_lines = nLines - visible_lines;
    if (excess_lines < 0) return 0;
    return (short)(excess_lines * lh);
}

static pascal void ScrollActionProc(ControlHandle c, short part)
{
    if (c != gResponseScroll) return;
    short delta = 0;
    switch (part) {
    case kControlUpButtonPart:   delta = -ResponseLineHeight(); break;
    case kControlDownButtonPart: delta =  ResponseLineHeight(); break;
    case kControlPageUpPart:     delta = -ResponsePageHeight(); break;
    case kControlPageDownPart:   delta =  ResponsePageHeight(); break;
    default: return;
    }
    short before = GetControlValue(c);
    short after  = ClampScroll(before + delta);
    if (after == before) return;
    SetControlValue(c, after);
    /* TEScroll sign convention: positive dv moves text DOWN (shows
     * content above); negative dv moves text UP (shows content below).
     * We stored scroll value as "pixels scrolled down," so to advance
     * (down arrow, down page) we need a NEGATIVE dv. */
    TEScroll(0, (short)(before - after), gResponseTE);
}

void ui_set_response(const char *text, size_t len)
{
    if (!gResponseTE) return;
    long l = (long)len;
    if (l > 32767L) l = 32767L;  /* TERec hard cap */
    TESetText((const char *)text, l, gResponseTE);
    if (gResponseScroll) {
        SetControlMaximum(gResponseScroll, ComputeMaxScroll());
        SetControlValue(gResponseScroll, 0);
    }
    InvalRect(&gResponseRect);
}

void ui_clear_response(void)
{
    ui_set_response("", 0);
}

void ui_set_status(const char *text)
{
    size_t n = strlen(text);
    if (n >= sizeof(gStatusText)) n = sizeof(gStatusText) - 1;
    memcpy(gStatusText, text, n);
    gStatusText[n] = '\0';
    InvalRect(&gStatusRect);
}

/* ── Public setters ── */

void ui_set_send_handler(SendHandler handler)
{
    gSendHandler = handler;
}

void ui_set_send_enabled(int enabled)
{
    if (!gSendBtn) return;
    HiliteControl(gSendBtn, enabled ? 0 : 255);
}

const char *ui_current_method(void)
{
    return kMethodNames[gMethodIndex];
}

int ui_handle_menu(long menuChoice)
{
    short menuID = HiWord(menuChoice);
    short item   = LoWord(menuChoice);

    switch (menuID) {
    case 130:   /* File */
        if (item == 1) return 1;   /* Quit */
        break;

    case 129:   /* Apple */
        /* Item 1 is "About Postman…"; items 3+ are DAs added via
         * AppendResMenu. For now we don't do anything useful — just
         * acknowledge the hit so the menu unhilites. */
        break;

    case 131:   /* Edit */
        /* All items disabled; nothing to do. Future: route to TECut/
         * TECopy/TEPaste for the focused TE. */
        break;

    default:
        break;
    }
    return 0;
}
