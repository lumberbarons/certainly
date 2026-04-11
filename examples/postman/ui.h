#ifndef POSTMAN_UI_H
#define POSTMAN_UI_H

#include <Windows.h>
#include <Events.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Called once at app startup after the Toolbox is initialized.
 * Creates the main window and all fields/controls. */
void ui_init(void);

/* Called once before the app exits. */
void ui_dispose(void);

/* Handle one event from WaitNextEvent. */
void ui_handle_event(const EventRecord *event);

/* Set by postman.c at startup. Called by ui.c when Send is clicked. */
typedef void (*SendHandler)(void);
void ui_set_send_handler(SendHandler handler);

/* Enable or disable the Send button (grays and stops hit tracking). */
void ui_set_send_enabled(int enabled);

/* Current HTTP method selection as an uppercase string: "GET",
 * "POST", "PUT", or "DELETE". Pointer is stable for the app's
 * lifetime; do not free. */
const char *ui_current_method(void);

/* Handle a menu-item hit (returned from MenuSelect or MenuKey).
 * menuChoice is the raw 32-bit result: HiWord = menu ID, LoWord = item.
 * Returns 1 if the app should quit as a result, 0 otherwise. */
int ui_handle_menu(long menuChoice);

#ifdef __cplusplus
}
#endif

#endif
