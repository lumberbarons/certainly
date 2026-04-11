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
#include <OpenTransport.h>
#include <stdio.h>
#include <string.h>

#include "certainly.h"
#include "ui.h"
#include "http.h"

int main(void)
{
    /* Standard Toolbox init */
    InitGraf(&qd.thePort);
    InitFonts();
    InitWindows();
    InitMenus();
    TEInit();
    InitDialogs(NULL);
    InitCursor();

    InitOpenTransport();
    MacTLS_Init();

    /* Tasks 6+ will create the real window here. For now, exit. */

    MacTLS_Shutdown();
    CloseOpenTransport();
    return 0;
}
