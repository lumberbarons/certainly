#include "Processes.r"
#include "SysTypes.r"
#include "Menus.r"

resource 'SIZE' (-1) {
    reserved,
    acceptSuspendResumeEvents,
    reserved,
    canBackground,
    doesActivateOnFGSwitch,
    backgroundAndForeground,
    dontGetFrontClicks,
    ignoreChildDiedEvents,
    is32BitCompatible,
    notHighLevelEventAware,
    onlyLocalHLEvents,
    notStationeryAware,
    dontUseTextEditServices,
    reserved,
    reserved,
    reserved,
    2 * 1024 * 1024,   /* 2 MB preferred — TLS + response buffer */
    1 * 1024 * 1024    /* 1 MB minimum */
};

resource 'MENU' (128, "Method") {
    128,
    textMenuProc,
    0x7FFFFFFF,
    enabled,
    "Method",
    {
        "GET",     noIcon, noKey, noMark, plain;
        "POST",    noIcon, noKey, noMark, plain;
        "PUT",     noIcon, noKey, noMark, plain;
        "DELETE",  noIcon, noKey, noMark, plain;
    }
};

resource 'MENU' (129, "Apple") {
    129,
    textMenuProc,
    0x7FFFFFFD,        /* disable "About" to match pre-selection style */
    enabled,
    apple,             /* apple logo character */
    {
        "About Postman\0xC9", noIcon, noKey, noMark, plain;
        "-",              noIcon, noKey, noMark, plain;
    }
};

resource 'MENU' (130, "File") {
    130,
    textMenuProc,
    allEnabled,
    enabled,
    "File",
    {
        "Quit", noIcon, "Q", noMark, plain;
    }
};

resource 'MENU' (131, "Edit") {
    131,
    textMenuProc,
    0x00000000,        /* all items initially disabled */
    enabled,
    "Edit",
    {
        "Undo",       noIcon, "Z", noMark, plain;
        "-",          noIcon, noKey, noMark, plain;
        "Cut",        noIcon, "X", noMark, plain;
        "Copy",       noIcon, "C", noMark, plain;
        "Paste",      noIcon, "V", noMark, plain;
        "Clear",      noIcon, noKey, noMark, plain;
    }
};
