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
