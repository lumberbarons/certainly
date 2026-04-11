# Postman for Mac OS 9 — Design

**Date:** 2026-04-11 (revised after adversarial review)
**Author:** Matt + Claude (brainstorming session)
**Status:** Design approved, pending implementation plan

## Revision history

- **v1 (2026-04-11 morning):** Hybrid Dialog Manager (DLOG/DITL) + userItem
  design with bundled picohttpparser. An adversarial review surfaced
  four spec-fatal bugs (filter-proc-never-fires-during-send,
  dialog-updates-stall, EditText Str255 trap, Send re-entrancy) plus
  serious doubts about picohttpparser's Retro68 compile. Full critique
  preserved below under "Why v2 replaces v1."
- **v2 (2026-04-11 afternoon):** Rewrite around a single manual
  `NewCWindow` with hand-managed `TEHandle`s, the same idiom as
  `simple_get`. HTTP response parsing is a 30-line inline scan.
  Eliminates the entire Dialog Manager / userItem / third_party surface.

## Goal

Interactive Postman-style HTTPS testing app, built as an example inside
the Certainly TLS library. Runs on classic Mac OS 9 (PowerPC), drives
Certainly for TLS 1.2/1.3 transport, and lets the user:

- Choose a method (GET / POST / PUT / DELETE) via a popup menu.
- Edit a URL field (pre-populated with `https://`).
- Edit a custom-headers multiline field (`Name: Value` per line).
- Edit a request body multiline field (used for POST/PUT; stripped for
  GET/DELETE).
- Click Send to issue the request.
- See the parsed HTTP status line in a prominent label.
- See response headers + body in a scrollable text pane.
- Cancel an in-flight request with Cmd-.

Single request at a time. No persistence across launches. No redirect
following, no keepalive, no chunked decoding, no auth, no collections.

## Non-goals

- Not a replacement for real Postman. This is a developer example.
- No automated test harness; testing is manual in SheepShaver.
- No saved collections or multi-request workflows.
- No WebSockets, HTTP/2, or anything above HTTP/1.1.

## Architecture

One hand-managed window, four caller-owned `TEHandle`s, one real
`ControlHandle` each for the Send button, the method popup, and the
response pane's scrollbar. No Dialog Manager. No bundled dependencies.
Same fundamental shape as `examples/simple_get`, scaled up to handle
multiple editable fields and a scrolling text view.

### Why this shape (and not the hybrid dialog from v1)

The original hybrid design paid the complexity tax of DLOG/DITL/userItem
without getting the Dialog Manager's benefits during the one phase that
matters — while a request is in flight. Inside our custom MacTLS pump
loop we can't be inside `ModalDialog`, so the filter proc never fires
(dead Cmd-. cancel), updates aren't dispatched to dialog items (frozen
status line), and `SetDialogItemText`/`GetDialogItemText` silently cap
fields at 255 bytes (broken POST body). Rather than layer patches onto
those problems, v2 drops the Dialog Manager entirely and uses one
event loop that's always running, always pumping Certainly when a
send is active, always routing events to our TE fields. This matches
the `simple_get` idiom, eliminates ~200 lines of userItem / draw-proc /
filter-proc glue, and lets us write code that's obviously correct.

### File layout

```
examples/postman/
├── CMakeLists.txt
├── postman.r                       — SIZE + MENU (method popup)
├── postman.c                       — main, event loop, send flow
├── http.c / http.h                 — URL parsing, request building, response split
└── ui.c / ui.h                     — window creation, TE fields, draw/click/key/focus
```

Three C source files, each with a single job:

- **`postman.c`** — app lifecycle. Toolbox init, create window, run event
  loop, dispatch events to `ui_*` handlers, drive `DoSendAndReceive`
  when Send fires, call `http_*` for parsing.
- **`http.c`** — pure string manipulation, no Toolbox calls. URL parse,
  request build, response split. Host-compilable if we ever want a
  unit test on the Mac side or the dev side.
- **`ui.c`** — everything visual. Window creation, TE field setup,
  focus tracking, draw/click/key dispatch to fields, scrollbar wiring,
  status-line drawing.

No `third_party/`. No bundled dependencies.

## Window layout

Plain document window, **560 × 400 pixels**, centered on the main
screen at window-open time. Created via `NewCWindow` (color
QuickDraw) with `documentProc` for a standard Mac OS 9 resizable
window chrome. No close box (we quit via Cmd-Q or File → Quit from the
menu bar).

```
┌──────────────────────────────────────────────────────────┐
│ Postman                                                  │
├──────────────────────────────────────────────────────────┤
│ Method: [GET ▼]  URL: [https://__________________] [Send]│
│                                                          │
│ Headers:                                                 │
│ ┌──────────────────────────────────────────────────────┐ │
│ │                                                      │ │
│ └──────────────────────────────────────────────────────┘ │
│ Body:                                                    │
│ ┌──────────────────────────────────────────────────────┐ │
│ │                                                      │ │
│ └──────────────────────────────────────────────────────┘ │
│ Status: (no request sent)                                │
│ Response:                                                │
│ ┌──────────────────────────────────────────────────┐[▲] │
│ │                                                  │[ ] │
│ └──────────────────────────────────────────────────┘[▼] │
└──────────────────────────────────────────────────────────┘
```

Approximate dimensions (tuned during implementation):

- **Method popup:** 70 × 20 px. We draw the current method as
  `"Method: GET"` inside a bordered rect; on mousedown we invert the
  rect and call `PopUpMenuSelect(gMethodMenu, globalPt.v, globalPt.h,
  currentItem)` which shows a standard Mac OS 9 popup and returns the
  selected item. No `CNTL` resource required.
- **URL field:** ~340 × 20 px, single-line `TEHandle`. Default text
  `https://` installed at window-open.
- **Send button:** 60 × 20 px. Real `ControlHandle` created with
  `NewControl(..., pushButProc, ...)`. Reason: we want `TrackControl`
  hit tracking, automatic grey-out on `HiliteControl(255)` that
  *actually* suppresses hit tracking (unlike with Dialog Manager
  items), and free default-button drawing on Return.
- **Headers TE:** ~520 × 55 px, multiline `TEHandle`, 3–4 visible lines,
  TE's own internal scrolling via `TEScroll` on up/down-arrow keys.
- **Body TE:** same dimensions as Headers.
- **Status line:** a drawn string in a known `Rect` (not a control,
  not a TE). Updated by `ui_set_status(const char *)` which stashes the
  text and calls `InvalRect(&gStatusRect)`; the redraw happens from our
  update-event handler. No flicker, no `SetDialogItemText` pitfalls.
- **Response pane:** a `TEHandle` inside a fixed `viewRect` plus a
  standard `scrollBarProc` `ControlHandle` glued to its right edge.
  Owned by `ui.c`, hand-wired with an action proc. Hard cap at
  32,767 bytes (TERec limit).

Keyboard:

- **Tab / Shift-Tab** — cycles focus between URL → Headers → Body →
  back to URL (skipping the response pane; it's not editable). We
  maintain `gFocusedTE` as a file-scope pointer; Tab advances it.
- **Return** — fires Send when focus is on the URL field. Inside
  Headers/Body, Return inserts a newline (normal TE behavior).
- **Cmd-.** — cancels an in-flight send. Handled inline in the event
  loop, not via a filter proc (there is no filter proc — there is no
  modal dialog).

## Event loop

**One loop, always running, regardless of send state.** This is the
single most important change from v1.

```c
int main(void) {
    /* Toolbox init, InitOpenTransport, MacTLS_Init, open window */

    while (!gQuit) {
        EventRecord event;
        WaitNextEvent(everyEvent, &event, gSleep, NULL);
        HandleOneEvent(&event);
        if (gSending) DriveSendStep();     /* one non-blocking pump step */
    }

    /* Cleanup */
}
```

`HandleOneEvent` is a normal classic-Mac event dispatcher:

| `event.what` | Action |
|---|---|
| `mouseDown` | `FindWindow` → if our window, route to `ui_handle_click(localPt)` |
| `keyDown` / `autoKey` | `ui_handle_key(event.message, event.modifiers)` |
| `updateEvt` | `BeginUpdate(w)` → `ui_draw_all()` → `EndUpdate(w)` |
| `activateEvt` | `ui_activate(event.modifiers & activeFlag)` — TE (de)activation and scrollbar HiliteControl |
| `osEvt` with `suspendResumeMessage` | same as activate/deactivate |
| `kHighLevelEvent` | Apple Events (handles required events for Finder quit) |

### `ui_handle_click(Point localPt)`

```
1. If PtInRect(localPt, &gMethodRect):
       invert, call PopUpMenuSelect, update gMethod, redraw method label.
       Done.

2. If PtInRect(localPt, &gSendRect) AND !gSending AND TrackControl(gSendBtn, ...):
       kick off DoSendAndReceive(). Done.

3. If PtInRect(localPt, &gResponseScrollRect):
       Dispatch to the scrollbar:
         partCode = FindControl(localPt, w, &ctl);
         if (ctl == gResponseScrollBar)
             TrackControl(ctl, localPt, gScrollActionUPP);
             after TrackControl returns, reconcile TE scroll to control value.
       Done.

4. If PtInRect(localPt, &gURLRect):
       focus_set(gURLTE);  TEClick(localPt, shift, gURLTE);  done.

5. Same for gHeadersRect, gBodyRect.

6. Otherwise: ignore.
```

### `ui_handle_key(long message, short modifiers)`

```
char c = (char)(message & charCodeMask);

1. if ((modifiers & cmdKey) && c == '.') {
       if (gSending) gCancelled = true;
       return;   /* do NOT pass . to the focused TE */
   }

2. if ((modifiers & cmdKey) && (c == 'q' || c == 'Q')) {
       gQuit = true; return;
   }

3. if (c == kTabChar) {
       focus_advance(modifiers & shiftKey);
       return;
   }

4. if (c == kReturnChar && gFocusedTE == gURLTE && !gSending) {
       kick off DoSendAndReceive();
       return;
   }

5. if (gFocusedTE) TEKey(c, gFocusedTE);
```

### `ui_draw_all(void)`

Called from inside `BeginUpdate/EndUpdate` during an update event, and
also called directly after a state change (status line text, response
text) via `InvalRect` + the normal update-event path. Draws:

```
1. EraseRect(&portRect)                   — clear the content region
2. For each label ("Method:", "URL:", "Headers:", etc.):
       MoveTo, DrawString
3. FrameRect around the Method popup
   DrawMethodLabel()  → "Method: GET" centered inside it
4. DrawControls(gWindow)                   — renders Send button,
                                             method popup (if it were
                                             a Control — it's not),
                                             and the response scrollbar
5. TEUpdate(&gURLViewRect,      gURLTE)
   TEUpdate(&gHeadersViewRect,  gHeadersTE)
   TEUpdate(&gBodyViewRect,     gBodyTE)
   TEUpdate(&gResponseViewRect, gResponseTE)
6. Draw status line:
       MoveTo(gStatusPt.h, gStatusPt.v)
       TextFont(geneva); TextSize(10)
       DrawString(gStatusText)
7. Frame each TE field with FrameRect(&fieldRect) for a visible border.
```

No flicker because the whole content region is erased and redrawn in
one pass during the update event, not field by field on every status
change.

## Send flow (`DoSendAndReceive` and `DriveSendStep`)

Unlike v1, the send is **split across multiple event-loop iterations**
instead of running its own inner pump. There is no inner pump. There
is no re-entrancy. There is no "am I inside ModalDialog or outside"
problem. Instead:

- `DoSendAndReceive` is the **synchronous prelude**: it reads fields,
  parses the URL, builds the request, allocates the MacTLS context,
  updates the status line, sets `gSending = true`, and returns.
- `DriveSendStep` is called once per main-loop iteration while
  `gSending` is true. It calls `MacTLS_Pump` once, handles the
  returned state (write request on first Connected, drain on Closed,
  etc.), and returns. The main loop calls it again next iteration.
- When the terminal state is reached (Closed, Error, or Cancelled),
  `DriveSendStep` finalizes: parses the response, updates the status
  line, installs the response text in `gResponseTE`, tears down the
  context, clears `gSending`, re-enables Send.

### `DoSendAndReceive` — the prelude

```
1. if (gSending) return;   /* re-entrancy guard — fixes v1 bug 10 */

2. Read fields:
       url_bytes     = TE handle text of gURLTE
       headers_bytes = TE handle text of gHeadersTE
       body_bytes    = TE handle text of gBodyTE (only if POST/PUT)
       method        = gMethod          (enum from popup)
   Each is a contiguous byte span — not Str255. No 255-byte cap.

3. http_parse_url(url_bytes, ..., &host, &port, &path).
   On failure: ui_set_status("Bad URL: <reason>"); return.

4. http_build_request(method, host, path, headers_bytes, body_bytes, ...).
   On overflow: ui_set_status("Request too large"); return.

5. ctx = MacTLS_Create(host, port);
   On NULL or Error state: ui_set_status(tls_error_string(ctx));
                           if (ctx) MacTLS_Close(ctx);
                           return.

6. gCtx = ctx;  gRequestSent = false;  gResponseLen = 0;
   gSending = true;  gCancelled = false;
   HiliteControl(gSendBtn, 255);           /* real disable */
   ui_set_status("Connecting to <host>:<port>...");
   return.
```

Nothing here blocks. After this returns, the main event loop resumes
with `gSending = true`, so `DriveSendStep` takes over.

### `DriveSendStep` — one iteration of progress

```
1. If gCancelled:
       ui_set_status("Cancelled");
       finalize_send();
       return;

2. state = MacTLS_Pump(gCtx);

3. Switch on state:
     Connecting / Handshaking:
         (optionally) update status line periodically with
         "Handshaking..." — maybe once per second based on TickCount.

     Connected:
         If !gRequestSent:
             MacTLS_Write(gCtx, gRequestBuf, gRequestLen);
             gRequestSent = true;
             ui_set_status("Reading response...");
         space = sizeof(gResponseBuf) - gResponseLen - 1;
         if (space == 0) {
             /* Response buffer full. Stop waiting for close we
              * can't drain toward. Finalize with what we have. */
             finalize_response(true /* truncated */);
             return;
         }
         n = MacTLS_Read(gCtx, gResponseBuf + gResponseLen, space);
         if (n > 0) {
             gResponseLen += n;
             /* cheap periodic status update without per-byte redraw:
              * only update when crossing 1 KB boundaries */
             if ((gResponseLen & ~1023) != (gPrevResponseLen & ~1023))
                 ui_set_status_fmt("Reading response (%d bytes)",
                                    (int)gResponseLen);
             gPrevResponseLen = gResponseLen;
         }
         return;

     Closed:
         /* Drain any remaining bytes. */
         loop {
             space = sizeof(gResponseBuf) - gResponseLen - 1;
             if (space == 0) break;
             n = MacTLS_Read(gCtx, gResponseBuf + gResponseLen, space);
             if (n <= 0) break;
             gResponseLen += n;
         }
         finalize_response(gResponseLen >= sizeof(gResponseBuf) - 1);
         return;

     Error:
         ui_set_status(format_tls_error(gCtx));
         finalize_send();
         return;
}
```

### `finalize_response(bool truncated)` and `finalize_send()`

```
finalize_response(bool truncated) {
    const char *status_line; size_t status_len;
    const char *headers;     size_t headers_len;
    const char *body;        size_t body_len;

    if (http_split_response(gResponseBuf, gResponseLen,
                            &status_line, &status_len,
                            &headers,     &headers_len,
                            &body,        &body_len) != 0) {
        /* Not a valid HTTP response. Show raw first 60 bytes and
         * a clear error status. */
        ui_set_status("Malformed HTTP response");
        ui_set_response_raw(gResponseBuf,
                            gResponseLen > 256 ? 256 : gResponseLen);
    } else {
        char status[256];
        snprintf(status, sizeof(status), "%.*s%s",
                 (int)status_len, status_line,
                 truncated ? "  (truncated to 32K)" : "");
        ui_set_status(status);
        ui_set_response_headers_and_body(headers, headers_len,
                                         body,    body_len);
    }
    finalize_send();
}

finalize_send() {
    if (gCtx) { MacTLS_Close(gCtx); gCtx = NULL; }
    gSending     = false;
    gCancelled   = false;
    HiliteControl(gSendBtn, 0);       /* re-enable */
}
```

**Invariant after `finalize_send`:** `gCtx == NULL`, `gSending == false`,
`gCancelled == false`, Send button enabled, status line reflects the
outcome. The main loop resumes normally.

### Between-request hygiene (OT cleanup)

`simple_get`'s multi-endpoint test taught us that Mac OS 9's Open
Transport can wedge after a failed async operation if we immediately
allocate a new provider. `simple_get` solved this by cycling
`InitOpenTransport` / `CloseOpenTransport` between tests plus yielding
60 ticks for notifiers to drain. Postman allocates a fresh MacTLS
context per Send, so we apply the same discipline:

- On app startup: one `InitOpenTransport` call.
- On app quit: one `CloseOpenTransport` call.
- Between requests: no cycling. Instead, after `MacTLS_Close`, the
  next Send cannot begin until the user clicks the button, which gives
  OT's notifier callbacks many hundreds of ticks to drain naturally
  (human reaction time is ~12 ticks minimum). We don't need an
  explicit delay here because the UI already provides one.

If in practice we see the same wedge that bit `simple_get`'s tight
loop, we'll add a `CloseOpenTransport`/`InitOpenTransport` cycle on
each `finalize_send`. Noted as a follow-up, not implemented in v2.

## HTTP layer (`http.c` / `http.h`)

Three functions, all pure C, all `(buf, len)` → caller-supplied
output buffers. No allocations.

```c
/* Parse scheme://host[:port]/path[?query]. Accepts http/https.
 * Default port 443 for https, 80 for http. Writes into caller
 * buffers. Returns 0 on success, -1 on malformed URL. */
int http_parse_url(const char *url,    size_t url_len,
                   char       *host_out, size_t host_cap,
                   uint16_t   *port_out,
                   char       *path_out, size_t path_cap);

/* Build an HTTP/1.1 request into out_buf.
 *
 *   - Derives Host: from the already-parsed host. Strips any
 *     user-supplied Host: header (avoids TLS SNI mismatch).
 *   - Always emits Connection: close.
 *   - Always emits User-Agent: Certainly/0.1 unless the user
 *     supplied one.
 *   - Emits Content-Length: N when body is non-NULL.
 *   - Parses user_headers as "Name: Value\r" or "Name: Value\n";
 *     strips leading/trailing whitespace; skips blank lines.
 *   - For GET and DELETE methods, ignores body and body_len
 *     entirely (strips them). This is explicit in the spec.
 *
 * Returns total bytes written, or -1 on overflow. */
int http_build_request(const char *method,
                       const char *host,
                       const char *path,
                       const char *user_headers, size_t user_headers_len,
                       const char *body,         size_t body_len,
                       char       *out_buf,      size_t out_cap);

/* Split a raw HTTP/1.1 response into status_line / headers / body.
 * All outputs are pointers into the caller's raw buffer; lifetimes
 * tied to raw. Returns 0 on success, -1 if raw doesn't look like
 * HTTP (missing CRLF or no blank-line terminator).
 *
 * Implementation notes:
 *   - status_line is the bytes up to the first \r\n (CRLF required).
 *   - headers starts at status_line_end + 2 and runs up to the first
 *     \r\n\r\n, which terminates the header region.
 *   - body starts at the end of that \r\n\r\n and runs to raw_len.
 *   - No Content-Length interpretation, no chunked decoding. We
 *     always send Connection: close so the body is "all bytes until
 *     the peer closes the socket," which is exactly gResponseBuf. */
int http_split_response(const char *raw, size_t raw_len,
                        const char **status_line_out, size_t *status_len_out,
                        const char **headers_out,     size_t *headers_len_out,
                        const char **body_out,        size_t *body_len_out);
```

Implementation budget: ~150 lines total. `http_split_response` is
about 30 lines — a single pass through the buffer looking for
`\r\n` and `\r\n\r\n`.

### Why no picohttpparser

The v1 reviewer correctly observed that our `parsed_response` only
uses status / headers-blob / body-blob. We don't walk the header
array, we don't case-insensitively compare header names, we don't
decode chunked, we don't handle header folding. A 30-line inline
scanner covers 100% of what we actually consume. Bundling
picohttpparser would add a `third_party/` directory, a LICENSE
vendoring decision, and — per the same reviewer — a real Retro68
compile risk around its `<sys/types.h>` / `ssize_t` dependency.
Not worth it.

If we later grow a need that picohttpparser actually provides —
reliable header folding, for example — we can revisit, and the
`http_*` API is narrow enough that swapping in picohttpparser
under `http_split_response` is a local change.

## Response pane (`ui.c`)

### Ownership

```c
static TEHandle       gResponseTE;
static ControlHandle  gResponseScrollBar;
static Rect           gResponseViewRect;     /* minus scrollbar column */
static ControlActionUPP gScrollActionUPP;
```

Created in `ui_init_window` at startup, disposed in `ui_dispose_window`
at shutdown.

### Scrollbar wiring

1. `NewControl(gWindow, &scrollRect, "\p", true, 0, 0, 0, scrollBarProc, 0)`
   creates the scrollbar at the right edge of the response pane.
2. An action proc handles in-arrow / in-page / in-thumb parts:
   ```c
   static pascal void ScrollAction(ControlHandle c, short part) {
       short delta = 0;
       switch (part) {
           case kControlUpButtonPart:   delta = -kLineHeight;   break;
           case kControlDownButtonPart: delta =  kLineHeight;   break;
           case kControlPageUpPart:     delta = -kPageHeight;   break;
           case kControlPageDownPart:   delta =  kPageHeight;   break;
           default: return;
       }
       short before = GetControlValue(c);
       short after  = ClampScroll(before + delta);
       SetControlValue(c, after);
       TEScroll(0, before - after, gResponseTE);
   }
   ```
3. On mouseDown inside the scrollbar rect, `ui_handle_click` calls
   `TrackControl(gResponseScrollBar, localPt, gScrollActionUPP)` which
   runs the action proc continuously until the mouse is released.
4. After `TrackControl` returns, we reconcile the TE scroll position
   to match the control's final value (in case the user dragged the
   thumb directly — `TrackControl` doesn't call the action proc for
   thumb drags).

### Installing response text

```c
void ui_set_response_headers_and_body(const char *headers, size_t hlen,
                                      const char *body,    size_t blen) {
    /* Build a display string into a scratch buffer on the stack:
     * headers + "\r" + body, with \n → \r conversion for TERec.
     * TERec uses \r (CR) as its line terminator, not \n. */
    static char disp[32768];
    size_t dlen = 0;

    dlen += copy_with_lf_to_cr_conversion(headers, hlen, disp + dlen,
                                          sizeof(disp) - dlen);
    if (dlen < sizeof(disp)) disp[dlen++] = '\r';
    dlen += copy_with_lf_to_cr_conversion(body, blen, disp + dlen,
                                          sizeof(disp) - dlen);
    if (dlen > 32767) dlen = 32767;        /* TERec hard cap */

    TESetText(disp, (long)dlen, gResponseTE);
    SetControlValue(gResponseScrollBar, 0);
    SetControlMaximum(gResponseScrollBar, compute_max_scroll(gResponseTE));
    InvalRect(&gResponseViewRect);
    /* Also InvalRect the scrollbar rect so DrawControls picks it up. */
}
```

### Truncation

TERec's 32,767-byte limit is a hard cap. If the combined headers + body
exceeds that, we truncate at the end. The status line then carries a
`(truncated to 32K)` suffix (assembled in `finalize_response`). This
matches what `simple_get`'s tester already does.

## Status line (`ui.c`)

The status line is **not** a control, **not** a TE field, and **not**
a Dialog Manager StaticText. It's a drawn string in a known `Rect`.

```c
static char gStatusText[256];
static Rect gStatusRect;

void ui_set_status(const char *text) {
    size_t n = strlen(text);
    if (n > sizeof(gStatusText) - 1) n = sizeof(gStatusText) - 1;
    memcpy(gStatusText, text, n);
    gStatusText[n] = '\0';
    InvalRect(&gStatusRect);
}

/* Called from ui_draw_all during BeginUpdate/EndUpdate. */
static void draw_status(void) {
    EraseRect(&gStatusRect);
    Str255 p;
    c2pstr_into(gStatusText, p);
    MoveTo(gStatusRect.left, gStatusRect.bottom - 4);
    TextFont(geneva); TextSize(10); TextFace(0);
    DrawString(p);
}
```

`ui_set_status_fmt` is a thin `snprintf` wrapper over `ui_set_status`.

### Status line values

| Phase | Status text |
|---|---|
| Startup | `(no request sent)` |
| URL parse error | `Bad URL: <reason>` |
| Request too large | `Request too large` |
| TLS context create failed | `TLS init failed: code=N OT=M` |
| Connecting | `Connecting to <host>:<port>...` |
| Handshaking | `Handshaking...` |
| Sending request | (transient, usually invisible) `Sending request...` |
| Reading | `Reading response (<N> bytes)` |
| Success | `<status_line>` e.g. `HTTP/1.1 200 OK` |
| Success + truncated | `HTTP/1.1 200 OK  (truncated to 32K)` |
| TLS error | `TLS error: code=N bssl=M` |
| Network error | `Network error: OT=<code>` |
| HTTP parse error | `Malformed HTTP response` |
| Cancelled | `Cancelled` |

## Focus management (`ui.c`)

```c
static TEHandle  gFocusedTE = NULL;   /* NULL if no field has focus */
static TEHandle  gFocusRing[] = { gURLTE, gHeadersTE, gBodyTE };
```

### Rules

- `focus_set(TEHandle te)`:
  ```
  if (gFocusedTE == te) return;
  if (gFocusedTE) TEDeactivate(gFocusedTE);
  gFocusedTE = te;
  if (gFocusedTE) TEActivate(gFocusedTE);
  ```
- `focus_advance(bool backward)`: rotates through `gFocusRing`.
- On window activate event: `if (gFocusedTE) TEActivate(gFocusedTE)`
  and call `HiliteControl(gResponseScrollBar, 0)`.
- On window deactivate: `if (gFocusedTE) TEDeactivate(gFocusedTE)`
  and call `HiliteControl(gResponseScrollBar, 255)`. The scrollbar
  grays out when our app is in the background.
- Click in an editable field calls `focus_set(thatField)` *before*
  `TEClick` so the activation flicker happens once, not twice.

## Error taxonomy

Three distinct classes, three distinct status-line messages:

1. **Input errors** (user fault, before any allocation): bad URL,
   request-too-large, missing scheme. Status line explains which field
   is wrong. Nothing is allocated, nothing to clean up.
2. **Transport / TLS errors** (server or network): `MacTLS_Create`
   failed, pump returned `kMacTLS_Error`. Status line shows our
   library's error codes verbatim — we already made `GetError` /
   `GetBearSSLError` meaningful for TLS 1.3 alerts during the
   `simple_get` work, so "TLS error: code=4 bssl=62" is as
   diagnostic as we can make it in one line.
3. **HTTP parse errors** (server sent something weird): response
   present but `http_split_response` returned -1. Status line says
   `Malformed HTTP response`; we dump the raw first ~256 bytes into
   the response pane so the user can see exactly what came back.

## Testing

Manual in SheepShaver. No automated harness.

1. **Smoke across the six known-good endpoints** from the
   `simple_get` multi-endpoint test: raw.githubusercontent.com,
   www.cloudflare.com, www.google.com, tls13.akamai.io,
   www.digicert.com, httpbin.org. GET each; verify the status line
   shows a sensible HTTP status and the response pane has text.
2. **Intentional URL errors:** mistyped scheme (`htps://`), missing
   scheme, unresolvable host (`no.such.host.example`). Verify each
   produces a user-facing "Bad URL: ..." in under a second and does
   not allocate an OT context.
3. **POST with JSON body:** POST to `https://httpbin.org/post` with a
   small JSON body and `Content-Type: application/json` in Headers.
   httpbin echoes what it received; verify the body round-trips and
   `Content-Length` is computed correctly.
4. **GET with body in body field:** type a body while method is GET,
   click Send. Verify the body is stripped and not sent (inspect
   httpbin's echo).
5. **Cancel mid-request:** start a send; hit Cmd-. during the
   handshake or while reading. Verify status shows `Cancelled`, Send
   re-enables, and a subsequent send to the same host works.
6. **Truncation:** GET a known-large page such as `www.google.com`
   (~80 KB). Verify status shows `(truncated to 32K)` and the
   response pane shows the first 32 KB without corruption.
7. **Re-entrancy:** while a request is in flight, press Return in the
   URL field and click Send. Verify neither action starts a second
   request; the first continues normally.
8. **Focus cycling:** Tab through URL → Headers → Body → URL. Verify
   the focus ring is only ever on one field at a time and that
   Shift-Tab goes backward.

## Known limitations (v2)

- Response pane capped at 32,767 bytes (TERec limit). Status line
  shows `(truncated to 32K)` when we hit the cap.
- No chunked transfer encoding. Mitigated by always sending
  `Connection: close`, which nudges servers toward definite-length
  bodies. If a server insists on chunked, the response pane shows
  the raw hex length markers.
- Single request at a time; no tabs, no history.
- No request persistence across launches.
- No redirect following (3xx shows in the response pane as-is).
- No HTTP authentication — users supply an `Authorization` header
  manually.
- GET/POST/PUT/DELETE only. No OPTIONS, PATCH, HEAD.
- Binary responses are rendered through TextEdit, which mishandles
  control characters and non-ASCII. JSON and HTML work; PNG bytes
  will look like nonsense.

## Why v2 replaces v1 (preserved critique)

The v1 Dialog Manager hybrid had four spec-fatal problems and several
smaller ones. Preserving the list here so the history is legible:

1. **Filter proc never fires during sends.** v1's filter proc was
   supposed to handle Cmd-. cancellation, but filter procs only run
   inside `ModalDialog`. v1's `DoSendAndReceive` ran its own pump
   loop, outside `ModalDialog`, so the filter proc was dead code for
   the one phase where cancellation is useful. v2 handles Cmd-.
   inline in the event loop — no filter proc, no `ModalDialog`.
2. **Dialog updates stall during sends.** v1's pump loop didn't call
   `IsDialogEvent` / `DialogSelect`, so the dialog couldn't redraw
   while a send was in flight. Status line updates were invisible,
   exposing the window over another app left it blank, and clicks
   were queued until the pump finished. v2's one-event-loop model
   makes this structurally impossible.
3. **`EditText` items silently cap at 255 bytes** when accessed via
   `GetDialogItemText` / `SetDialogItemText` (which use `Str255`).
   v1 didn't address this; a POST JSON body > 255 bytes would have
   been silently truncated. v2 owns `TEHandle`s directly and accesses
   them via TE's native byte-length API — no Str255 round-trip.
4. **Re-entrancy.** v1's `HiliteControl(255)` on a dialog button item
   grays the button visually but does not prevent `ModalDialog` from
   dispatching a hit on that item. v1 lacked an early-return guard.
   v2 has an explicit `if (gSending) return;` at the top of
   `DoSendAndReceive`, plus `HiliteControl(255)` on a real
   `ControlHandle` (which `TrackControl` respects for real).
5. **picohttpparser Retro68 risk.** v1 proposed vendoring
   picohttpparser for response parsing. It depends on `<sys/types.h>`
   and `ssize_t`, neither of which are guaranteed in Retro68's
   Universal Interfaces. v2 replaces it with a 30-line inline scan.
6. **popup menu complexity handwaved.** v1 said "CNTL 128, popup
   menu" without specifying the `popupMenuProc` procID or the
   separate `MENU` resource required. v2 uses `PopUpMenuSelect`
   against a bare `MENU` resource with no `CNTL` at all, which is
   both simpler and more flexible.
7. **`DrawControls` from inside a userItem draw proc** would have
   redrawn *every* control in the dialog on every response-pane
   refresh. v2 has no userItem draw proc.
8. **GET + body not specified.** v2 explicitly strips body for GET
   and DELETE inside `http_build_request`.
9. **Suspend/resume not handled.** v2's event loop dispatches `osEvt`
   suspend/resume through the same path as `activateEvt`.

None of these were unfixable individually, but fixing them all in a
Dialog Manager app would have produced a design that was strictly
worse than the NewCWindow idiom we already use in `simple_get`. v2
is simpler *and* more correct.
