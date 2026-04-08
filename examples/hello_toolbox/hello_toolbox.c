/*
 * hello_toolbox.c — minimal Mac OS 9 app
 *
 * What this does:
 *   1. Initializes the Mac OS Toolbox managers (every Mac app must do this)
 *   2. Opens a window
 *   3. Draws "Hello from Certainly!" in the window
 *   4. Waits for a mouse click, then quits
 *
 * What to learn from this:
 *   - The Toolbox Init sequence is boilerplate but mandatory
 *   - Windows are GrafPorts — you draw into them with QuickDraw
 *   - WaitNextEvent is how you yield to the OS and get input
 */

#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Menus.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Events.h>

int main(void)
{
    Rect        windowRect = {40, 40, 200, 400};
    WindowPtr   window;
    EventRecord event;

    /* Initialize every Toolbox manager. Order matters for some of these. */
    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    /* Create a visible window with a title */
    window = NewWindow(
        NULL,           /* let the OS allocate storage */
        &windowRect,    /* position and size */
        "\pCertainly",  /* title (Pascal string — \p prefix) */
        true,           /* visible immediately */
        documentProc,   /* standard document window style */
        (WindowPtr)-1,  /* in front of all other windows */
        false,          /* no close box */
        0               /* refCon — app-defined data, unused here */
    );

    SetPort(window);
    MoveTo(20, 80);
    DrawString("\pHello from Certainly!");
    MoveTo(20, 110);
    DrawString("\pClick anywhere to quit.");

    /* Wait for a mouse click */
    do {
        WaitNextEvent(everyEvent, &event, 30, NULL);
    } while (event.what != mouseDown);

    DisposeWindow(window);
    return 0;
}
