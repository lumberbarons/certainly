# Postman for Mac OS 9 — Design

**Date:** 2026-04-11
**Author:** Matt + Claude (brainstorming session)
**Status:** Design approved, pending implementation plan

## Goal

Build an interactive "Postman-style" HTTPS testing app as an example inside
the Certainly TLS library. It runs on classic Mac OS 9 (PowerPC), uses
Certainly for TLS 1.2/1.3 transport, and lets the user:

- Choose a method (GET / POST / PUT / DELETE).
- Edit a URL field (pre-populated with `https://`).
- Edit a custom-headers multiline field (one `Name: Value` per line).
- Edit a request body multiline field (used for POST/PUT).
- Click Send to issue the request.
- See the parsed HTTP status line in a prominent label.
- See the response headers + body in a scrollable text pane.
- Cancel an in-flight request with Cmd-.

No request persistence, no keepalive, no redirect following, no chunked
decoding, no auth, no collections. Single-request at a time. Modal dialog.

## Non-goals

- Not a replacement for real Postman. This is a developer example that
  exercises the Certainly library against real-world endpoints with a
  realistic UI, and teaches classic Mac OS Toolbox patterns along the way.
- No automated test harness. Testing is manual in SheepShaver.
- No support for saved request collections or multi-request workflows.
- No support for WebSockets, HTTP/2, or any protocol above HTTP/1.1.

## Architecture

Hybrid approach: Dialog Manager (DLOG/DITL resources) for the request form,
userItem with a hand-rolled `TEHandle` + scrollbar for the response pane.

The request form is exactly what DITL was designed for: static labels next
to edit fields with a default button. The response pane needs dynamic text
larger than `Str255`, which is the one case where a userItem + `TEHandle`
is the idiomatic classic Mac OS pattern. This keeps most of the UI
declarative (labels, fields, button, focus/tab, keyboard dispatch) while
giving us a real scrolling text view where we need it.

### File layout

```
examples/postman/
├── CMakeLists.txt
├── postman.r                           — SIZE + DLOG + DITL + CNTL
├── postman.c                           — main, event loop, send flow
├── http.c / http.h                     — URL parsing, request building
├── ui.c / ui.h                         — userItem draw proc, TE + scrollbar
└── third_party/picohttpparser/
    ├── LICENSE                         — MIT, preserved verbatim
    ├── picohttpparser.c                — unmodified upstream copy
    └── picohttpparser.h
```

Four C source files, each with one job:

- **`postman.c`** — owns the app lifecycle: Toolbox init, open dialog,
  modal event loop, dispatch itemHits, drive Certainly, call into http.*
  and ui.*.
- **`http.c`** — pure string manipulation. URL parsing, HTTP request
  building, thin wrapper around picohttpparser's response parsing. No
  Toolbox calls. Host-compilable if we ever want a unit test.
- **`ui.c`** — userItem draw proc, TE field helpers, scrollbar wiring,
  truncation logic. Encapsulates the scrolling text-view idiom.
- **`postman.r`** — resource file: SIZE, DLOG, DITL, one CNTL for the
  method popup.

### Bundled dependencies

We vendor picohttpparser (h2o project, MIT license, ~600 LOC) in
`third_party/picohttpparser/` with the upstream LICENSE file preserved
verbatim. picohttpparser handles:

- Response status-line parsing (version, code, reason phrase).
- Response header parsing into a caller-owned `phr_header[]` array.
- Header folding, lenient whitespace, edge cases in CRLF placement.
- Zero allocations — pure `(buf, len)` → pointers into the caller buffer.

We use `phr_parse_response` directly from `http.c`'s wrapper and don't
expose picohttpparser's types to `postman.c` or `ui.c`. If we swap
parsers later, only `http.c` changes.

## Window layout

Dialog window, **560 × 400 pixels**, centered on screen. Comfortable on
Mac OS 9's standard 640 × 480 display, fits on 800 × 600 with margin.

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

Approximate dimensions (to be tuned during implementation):
- Method popup: 70 px wide.
- URL field: ~340 px wide, single-line, default `https://`.
- Send button: 60 px wide, marked as the default button in the DITL.
- Headers TE: ~520 × 55 px, 3–4 visible lines, internal TE scroll.
- Body TE: ~520 × 55 px.
- Status line: StaticText, ~520 × 16 px.
- Response userItem + scrollbar: ~520 × 110 px with a vertical
  scrollbar (`scrollBarProc`, 16 px wide).

Keyboard (provided by the Dialog Manager automatically):
- Tab / Shift-Tab cycles editable fields.
- Return fires Send (the default button).
- Cmd-. cancels an in-flight request (handled in our filter proc).

## Resource file (`postman.r`)

Three resource types:

### `SIZE (-1)`

Memory hints to Finder. 2 MB preferred, 1 MB minimum — TLS buffers plus
a 32 KB response pane plus Toolbox overhead. Flags match `simple_get`.

### `DLOG (128)`

```
resource 'DLOG' (128) {
    {40, 10, 440, 570},
    movableDBoxProc,
    visible, noGoAway,
    0x0, 128, "Postman"
};
```

`movableDBoxProc` gives us a modal dialog with a title bar the user can
drag — the conventional Mac OS 9 choice for tool dialogs that shouldn't
be closable via a go-away box but that should be repositionable.

### `DITL (128)`

Twelve items. Item numbers are the dialog's ABI; C code uses
`#define`-d constants that must stay in sync with the resource file.

| # | Type       | Constant             | Notes                         |
|---|------------|----------------------|-------------------------------|
| 1 | Button     | `kItemSend`          | Default button                |
| 2 | StaticText | —                    | "Method:"                     |
| 3 | Control    | `kItemMethod`        | Popup menu (CNTL 128)         |
| 4 | StaticText | —                    | "URL:"                        |
| 5 | EditText   | `kItemURL`           | Initial text: `https://`      |
| 6 | StaticText | —                    | "Headers:"                    |
| 7 | EditText   | `kItemHeaders`       | Multiline                     |
| 8 | StaticText | —                    | "Body:"                       |
| 9 | EditText   | `kItemBody`          | Multiline                     |
| 10| StaticText | `kItemStatus`        | Status line, updated at runtime |
| 11| StaticText | —                    | "Response:"                   |
| 12| UserItem   | `kItemResponseUI`    | Draw proc installed at runtime |

Items 2, 4, 6, 8, 11 are disabled in Rez-speak (don't emit item hits).
Item 12 is a userItem whose draw proc is bound via `SetDialogItem` in
`InitPostmanDialog()`.

### `CNTL (128)` — method popup

A classic Mac OS popup menu control. Four items: GET, POST, PUT, DELETE.
The C code reads the current selection via `GetControlValue` when the
user clicks Send.

## Event loop and dispatch

### Main loop

```c
while (!quit) {
    ModalDialog(gFilterUPP, &itemHit);
    switch (itemHit) {
        case kItemSend: DoSendAndReceive(dlg); break;
        /* ...window close / quit handling... */
    }
}
```

`ModalDialog` is a blocking event pump with built-in routing. It calls
`WaitNextEvent` internally, hands EditText events to TE, dispatches
clicks on Button items as itemHits, and calls our userItem draw proc on
update events. Most of the app is inside `ModalDialog` except during an
active send.

### Filter proc

Our filter proc handles one thing: Cmd-. during an in-flight request.
When `gSending` is true, Cmd-. sets `gCancelled = true` and returns
`true` to indicate the event was consumed. Otherwise it returns `false`
and lets `ModalDialog` do its default thing (Return fires default
button, etc.).

### `DoSendAndReceive`

Called synchronously from the `kItemSend` branch, but internally runs
its own event pump so the app stays responsive during the handshake and
download:

```
1. Read field contents into local buffers (URL, method, headers, body).
2. http_parse_url() the URL → host, port, path.
   On failure: set status "Bad URL: <reason>", return.
3. http_build_request() into a 32 KB send buffer.
   On overflow: set status "Request too large", return.
4. SetDialogItemText(status, "Connecting to <host>:<port>...");
   HiliteControl(send button, 255);  /* disable */
   gSending = true;  gCancelled = false;
5. ctx = MacTLS_Create(host, port);
   On NULL or kMacTLS_Error: set status to TLS error, cleanup, return.
6. Pump loop:
      while (!done) {
          WaitNextEvent(everyEvent, &event, 1, NULL);
          /* Let ModalDialog filter-style input drain (Cmd-.). */
          if (gCancelled) break;
          state = MacTLS_Pump(ctx);
          switch (state) {
              case kMacTLS_Connecting / Handshaking:
                  update status line periodically;
                  break;
              case kMacTLS_Connected:
                  if (!requestSent) { MacTLS_Write(...); requestSent = true; }
                  read response into response_buf; update status with byte count;
                  break;
              case kMacTLS_Closed:
                  drain any remaining bytes;
                  done = true;
                  break;
              case kMacTLS_Error:
                  record error; done = true;
                  break;
          }
      }
7. If gCancelled: status = "Cancelled", MacTLS_Close, cleanup, return.
8. If error: status = formatted TLS/OT error, MacTLS_Close, cleanup, return.
9. http_parse_response(response_buf, len) → struct parsed_response.
   On parse failure: status = "Malformed HTTP response",
   push raw first 60 bytes to response pane, cleanup, return.
10. Set status line to parsed status line (or "(truncated to 32K)" if hit cap).
11. ui_set_response_text(parsed.body, parsed.body_len) — also shows
    headers above the body, separated by a blank line.
12. MacTLS_Close(ctx); gSending = false;
    HiliteControl(send button, 0); /* re-enable */
```

Steps 1–3 are pure C validation before any network allocation. Steps
5–12 are the network/UI phase. Errors in each phase cleanly tear down
only what was allocated up to that point.

### Dispatch table

| itemHit       | Action                                              |
|---------------|-----------------------------------------------------|
| `kItemSend`   | `DoSendAndReceive(dlg)`                             |
| `kItemMethod` | Popup handled by Control Manager; no C-side action  |
| `kItemURL`    | EditText, no action on hit                          |
| `kItemHeaders`| EditText, no action on hit                          |
| `kItemBody`   | EditText, no action on hit                          |
| `kItemStatus` | Disabled, doesn't fire                              |
| `kItemResponseUI` | Disabled, no hit; draw proc only                |

## HTTP layer (`http.c` / `http.h`)

### Our hand-rolled code

```c
/* Parse scheme://host[:port]/path[?query]. Only http/https accepted.
 * Default port 443 for https, 80 for http. Writes into caller buffers.
 * Returns 0 on success, -1 on malformed URL. */
int http_parse_url(const char *url,
                   char       *host_out, size_t host_cap,
                   uint16_t   *port_out,
                   char       *path_out, size_t path_cap);

/* Build a complete HTTP/1.1 request into out_buf. Derives Host from
 * the already-parsed host. Always emits Connection: close. Always
 * emits User-Agent: Certainly/0.1 unless the user supplied one.
 * Emits Content-Length: N automatically when body is non-NULL. Parses
 * user_headers as "Name: Value\n..." (accepts \n or \r\n), trims
 * whitespace, skips blank lines. Returns bytes written, or -1 on
 * overflow. */
int http_build_request(const char *method,
                       const char *host,
                       const char *path,
                       const char *user_headers, /* may be NULL */
                       const char *body,         /* may be NULL */
                       size_t      body_len,
                       char       *out_buf,
                       size_t      out_cap);
```

### picohttpparser wrapper

```c
struct parsed_response {
    int          status;           /* 200, 404, ... */
    const char  *reason;           /* "OK" — pointer into raw buffer */
    size_t       reason_len;
    const char  *headers_raw;      /* start of headers region */
    size_t       headers_len;
    const char  *body;             /* start of body */
    size_t       body_len;
};

/* Parse a raw HTTP/1.1 response in place. All pointers in *out
 * reference the caller's raw buffer; lifetime is tied to raw.
 * Returns 0 on success, -1 on parse failure. */
int http_parse_response(const char *raw, size_t raw_len,
                        struct parsed_response *out);
```

Internally calls `phr_parse_response`, translates picohttpparser's
return value (offset of body start) to our `body`/`body_len` pair,
walks the `phr_header[]` to reconstruct `headers_raw`/`headers_len`
(end offset = `raw + body_start_offset - 4`, trimming the `\r\n\r\n`).

### Design rules enforced by `http_build_request`

- **Host header is library-controlled**, not user-overridable. TLS SNI
  uses the URL's host for `MacTLS_Create`; a mismatching `Host:` header
  is a silent footgun that causes 421 Misdirected Request or worse.
  Users cannot provide their own `Host:` — we strip it if present.
- **Connection: close is always emitted.** Certainly is not keepalive
  capable, and `close` triggers servers to send a definite-length
  body (avoiding chunked encoding we don't decode).
- **Content-Length is auto-computed** from the body buffer, ignoring
  any user-supplied value.

## Response pane (`ui.c` / `ui.h`)

### Ownership

File-scope state inside `ui.c`:

```c
static TEHandle       gResponseTE;
static ControlHandle  gResponseScrollBar;
static Rect           gResponseViewRect;   /* minus scrollbar column */
static UserItemUPP    gDrawResponseUPP;
```

Exposed to `postman.c` through a small set of functions:

```c
void ui_init_response(DialogPtr dlg);                    /* at startup */
void ui_set_response_text(const char *headers,  size_t headers_len,
                          const char *body,     size_t body_len);
void ui_set_response_error(const char *msg, const char *raw, size_t raw_len);
void ui_dispose_response(void);                          /* at shutdown */
```

### Draw proc

```c
static pascal void DrawResponsePane(DialogPtr dlg, short itemNo)
{
    if (itemNo != kItemResponseUI) return;
    TEUpdate(&gResponseViewRect, gResponseTE);
    DrawControls(GetDialogWindow(dlg));
}
```

Installed once at dialog-open time with:

```c
Handle h; short t; Rect box;
GetDialogItem(dlg, kItemResponseUI, &t, &h, &box);
SetDialogItem(dlg, kItemResponseUI,
              userItem + itemDisable,
              (Handle)gDrawResponseUPP, &box);
```

### Scrollbar

Created at dialog-open time in the rightmost 16 px of the response
bounds via `NewControl(..., scrollBarProc, ...)`. Action proc handles
the arrow/page clicks via `TEScroll`; direct-thumb drags are
reconciled after `TrackControl` returns by reading `GetControlValue`
and calling `TEScroll` to match.

Click routing: the filter proc detects mouse-downs inside the
scrollbar's rect and calls `TrackControl(control, localPt, actionProc)`
before letting `ModalDialog` process the event. If the click misses
the scrollbar, we return `false` and let the Dialog Manager handle it.

### Text insertion

```c
void ui_set_response_text(const char *headers, size_t headers_len,
                          const char *body,    size_t body_len)
{
    /* Build a display string: headers + "\r\r" + body.
     * TERec uses \r as line separator on classic Mac OS, not \n.
     * Convert \n / \r\n in the source to \r. */
    size_t display_len;
    char *display = build_display_buffer(headers, headers_len,
                                         body, body_len, &display_len);
    if (display_len > 32767) display_len = 32767;  /* TE hard limit */

    TESetText(display, (long)display_len, gResponseTE);
    SetControlValue(gResponseScrollBar, 0);
    SetControlMaximum(gResponseScrollBar,
                      ComputeMaxScroll(gResponseTE, &gResponseViewRect));
    InvalRect(&gResponseViewRect);
}
```

### Truncation

TERec has a hard 32,767-byte limit. If the combined headers + body
exceeds that, we truncate the *tail* (showing headers + whatever body
fits) and set the status line's suffix to `(truncated to 32K)`. A
future version could use TextEdit's lower-level `TEStyleNew` + custom
insertion to raise this limit, but that's out of scope for v1.

## Error handling and status feedback

The `kItemStatus` StaticText is the only user-visible channel for
runtime status. It cycles through the following states:

| Phase | Status text |
|---|---|
| Startup | `(no request sent)` |
| URL parse error | `Bad URL: <reason>` |
| Request too large | `Request too large` |
| TLS context create failed | `TLS init failed: code=N OT=M` |
| Connecting | `Connecting to <host>:<port>...` |
| Handshaking | `TLS handshake...` |
| Sending request | `Connected — sending request` |
| Reading | `Reading response (<N> bytes)` |
| Success | `HTTP/1.1 <code> <reason phrase>` |
| Success + truncated | `HTTP/1.1 <code> <reason>  (truncated to 32K)` |
| TLS error | `TLS error: code=N bssl=M` |
| OT error | `Network error: OT=<code>` |
| HTTP parse error | `Malformed HTTP response` |
| Cancelled | `Cancelled` |

### Cancellation

`gCancelled` is a file-scope bool. The filter proc sets it to true when
Cmd-. is pressed during a send. `DoSendAndReceive`'s pump loop checks
it every iteration and, if set, calls `MacTLS_Close(ctx)` (which
already handles mid-handshake teardown cleanly, verified with
`simple_get`) and returns to the caller with status line set to
`Cancelled`.

### Cleanup invariant

At the end of `DoSendAndReceive`, regardless of error or success, the
following invariant holds:

```c
ctx == NULL;            /* MacTLS_Close called, pointer zeroed */
gSending = false;
gCancelled = false;
HiliteControl(sendBtn, 0);  /* Send button re-enabled */
```

The dialog is always in one of two observable states: **idle**
(Send enabled, ready for input) or **sending** (Send disabled, status
line updating, Cmd-. cancellable). Never stuck in between.

## Testing

Manual testing in SheepShaver. No automated test harness.

1. **Smoke against known-good endpoints.** The same six hosts we tested
   with `simple_get`: raw.githubusercontent.com, www.cloudflare.com,
   www.google.com, tls13.akamai.io, www.digicert.com, httpbin.org. GET
   each; verify the status line shows a sensible HTTP status and the
   response pane has text.
2. **Intentional URL errors.** Mistyped scheme (`htps://`), missing
   scheme, unresolvable host (`no.such.host.example`), wrong port
   (`:444`). Verify the status line identifies the error class (URL
   vs. network) correctly.
3. **POST with body.** POST to `https://httpbin.org/post` with a small
   JSON body and `Content-Type: application/json`. httpbin echoes the
   request back; verify our body and headers round-trip correctly.
4. **Cancel mid-request.** Start a send; hit Cmd-. during the
   handshake or while reading. Verify the status line shows
   `Cancelled`, the Send button re-enables, and a subsequent send to
   the same host works.
5. **Truncation.** GET a known-large page such as `www.google.com`
   (whose landing page is ~80 KB). Verify the status line shows
   `(truncated to 32K)` and the response pane shows the first 32 KB
   without corruption.

## Known limitations (v1)

- Text response pane capped at 32 KB (TERec limit).
- No support for chunked transfer encoding. Mitigated by always
  sending `Connection: close`, which nudges servers toward
  definite-length bodies.
- Single request at a time; no tabs or history.
- No request persistence across launches.
- No following of 3xx redirects.
- No support for HTTP auth; users must supply an `Authorization`
  header by hand.
- GET/POST/PUT/DELETE only. No OPTIONS, PATCH, HEAD.
- No binary response viewing — arbitrary bytes are rendered through
  TextEdit which will mishandle control characters.
