# ezxfer — developer guide

How the code fits together, and what to know before changing it. User-facing docs are in the [README](../README.md).

## Big picture

```
 browser A ──WebSocket──▶ ezxfer (C) ──WebSocket──▶ browser B
 (web/index.html)        sessions + relay         (web/index.html)
```

- **The server** (`src/`) serves the page and relays WebSocket messages between the two devices of a *session*. It doesn't understand files. Its only application-level messages are `hello`, `peer`, `error`, `pong`, plus answering `ping`.
- **The page** (`web/index.html`) implements everything else: offers, flow control, resume, the save paths and the UI. Both devices run the same code.
- **The service worker** (`web/sw.js`) streams downloads to disk where there is no save dialog.

## Build

`make` turns the web files into C headers with `tools/embed.c` (`build/index_html.h`, `build/sw_js.h`), then compiles everything into `ezxfer`. OpenSSL is linked when `pkg-config` finds it; `TLS=0` or `TLS=1` overrides that. `src/tls.c` compiles to stubs without `-DEZX_TLS`.

| File | Role |
|---|---|
| `src/main.c` | Option parsing → `server_config` → `server_run()` |
| `src/server.c` | Event loop, connections, sessions, HTTP routes, relay, startup banner |
| `src/proto.c` | Pure parsing: HTTP request head, query strings, WebSocket frames (unit-tested) |
| `src/tls.c` | OpenSSL behind a tiny non-blocking API (`tls_read/write/handshake/pending`) |
| `src/sha1.c` | SHA-1 + Base64 for the WebSocket handshake |
| `src/qr.c` | QR encoder (byte mode, versions 1–40) + SVG |
| `web/index.html` | The whole app: HTML, CSS and one IIFE script |
| `web/sw.js` | Service worker for streamed downloads |

## Server (`src/server.c`)

**Event loop.** A single thread runs `poll()` over the listening socket and up to `MAX_CONNS` connections. Each round:
- builds the poll set (`POLLIN` unless backpressured, `POLLOUT` if output is pending);
- reads, parses and relays, then flushes;
- once a second, calls `housekeeping()`: idle HTTP timeouts, WebSocket pings, and expiring empty sessions.

There are no threads and no locks.

**A connection** (`conn`) has an input buffer, an output buffer (`buffer` with a consumed-prefix offset) and a fragment buffer, and goes through these stages:

1. `accept_new()`
2. With TLS only: `TS_DETECT` → `TS_HANDSHAKE` → `TS_READY`, in `tls_progress()`. Detect peeks at the first byte: `0x16` is a TLS ClientHello, anything else is plain HTTP, which gets a 301 to `https://`.
3. `handle_http()` → route:
   - `/` serves the pre-rendered page
   - `/qr.svg?d=` returns a QR code
   - `/sw.js` serves the service worker
   - `/ws` upgrades the connection: `ws_upgrade()`
   - `/health`
4. `handle_ws()`: parse frames, answer `ping`/`close`, reassemble fragments, and `relay()` data frames to the peer **unchanged**.
5. `conn_free()` → `session_detach()`, which tells the peer `peer {connected:false}`.

All socket I/O goes through `io_read()` / `io_write()`, which hide plain versus TLS. `poll()` can't see data OpenSSL has already decrypted, so the loop forces a read when `tls_pending()` is non-zero.

**Backpressure.** The server stops reading from a connection while its peer has more than `OUT_HIGH_WATER` (4 MB) of unsent output. Combined with the page's ack window, memory stays bounded however large the file is.

**Sessions.** A session has a 6-character code and two slots. Joins are handled in `ws_upgrade()`:
- `?s=CODE` joins an existing session; without it, a new session is created.
- `?c=<client id>` identifies the page. A join whose client id matches an occupied slot **replaces** that connection (closed with 4001), because the device reconnected before the server noticed the old connection died.
- An empty session is kept for `--session-timeout` seconds, so devices can come back.

**Build id.** The server hashes (FNV-1a) the served page and service worker at startup. `{{VERSION}}` and `{{BUILD}}` are substituted once, in `render_page()`. `hello` carries the build id; a page with a different one reloads itself. That's why a page left open across an upgrade never speaks an old protocol.

## Protocol

The server-sent messages and the full list of message types are in the README's *Protocol* section. The flows:

```
sender                         receiver
offer {id,name,size,mime}  ─▶  (Accept / Decline shown)
                           ◀─  accept {id, offset:0}        (or decline)
binary [id|offset|data]... ─▶  written in order; ack {id,bytes} every 1 MB
eof {id}                   ─▶  verify size, finish, done {id}
```

- **Transfer ids** are chosen by the sender, unique per page load, and start at a random value. The receiver keys transfers as `peerId:id`.
- **Binary messages** are a 12-byte big-endian header (`u32` id, `u64` offset) plus up to 1 MB of data. The receiver ignores any chunk whose offset isn't exactly the number of bytes it has received.
- **Resume:** when the same device (same client id) reconnects, each side replays what may have been lost: offers, cancels, declines and dones. The receiver sends `accept {offset: bytes received}`, and the sender continues from there. Leftover data from before the drop fails the offset check and is dropped.
- **`info {instance}`** tells a reloaded peer page apart from a reconnected one. Transfers with a reloaded page fail, since its files and partial downloads are gone.
- **`picking {active, what}`:** a file picker (`open`) or save-location prompt (`save`) is open. A connection drop during it isn't reported, for up to 2 minutes.

## Page (`web/index.html`)

It's one IIFE, in sections marked `// ---------- name ----------`.

**Connection.**
- `connect()` / `socketLost()`: reconnect with backoff to the same session.
- `wakeUp()`: on returning to the page, reconnect or run `checkAlive()`. That's a `ping` the server answers, used to detect silently dead sockets.
- `onMessage()` dispatches every JSON message.

**Transfers** are plain objects in `outgoing` (by id) and `incoming` (by `peerId:id`). Their states:

```
outgoing: offered ─▶ sending ─▶ finishing ─▶ done
incoming: offered ─▶ saving ─▶ receiving ─▶ done
          (any active state ─▶ declined | cancelled | failed, via endOut()/endIn())
```

- `OUT_ACTIVE` and `IN_ACTIVE` list the states in which a transfer can still change.
- `paused` is a flag, not a state: the transfer waits for a reconnect (`pauseActive()`, `resumeWithPeer()`).

**Sending.** `pump()` sends one transfer at a time. Each chunk is `ws.send(new Blob([header, file.slice()]))`: the browser reads the file, with no copy in JavaScript. The loop pauses while 16 MB are unacknowledged (`MAX_INFLIGHT`). It's woken by acks (`kickPump()`), **not by timers**, because browsers throttle timers in background tabs. `onAccepted()` first reads one byte of the file, because an unreadable Blob would make the browser kill the whole WebSocket.

**Receiving.** `acceptIncoming()` picks a writer. All three have the same `write/close/abort` interface:

1. `showSaveFilePicker()`: desktop Chrome/Edge, in a secure context;
2. `streamWriter()`: the service worker, on a secure context that isn't iOS;
3. none: chunks collected in memory, then saved with `download()`.

Writes are chained on `t.chain`; acks are sent after each write.

**Service worker** (`web/sw.js`). The page registers a download (name, size, type) and passes a `MessagePort`, then opens `/dl/<random>/<name>` in a hidden iframe. The worker answers that request with a streaming `Response` fed through the port. Each chunk is acknowledged only when the download has room, which is how backpressure reaches the sender. The page pings the worker every 10 s while a download is open, to keep it alive. The worker must stay a separate, root-level file: browsers don't register inline service workers, and its scope must cover `/dl/`.

**Rendering.** `render(t)` marks a row dirty; `draw(t)` redraws it at most once per animation frame.

**Other parts:**
- `updateWakeLock()` keeps the screen on while transfers are busy.
- `setPicking()` / `setPeerPicking()` implement the "Choosing files…" and "Choosing where to save…" status.
- `window.ezxfer` exposes state and fault injection (`dropConnection`, `freezeConnection`) **for the tests only**.

## Tests

```sh
make test   # everything; the TLS suites too when built with TLS
```

| Suite | Tool | What it covers |
|---|---|---|
| `tests/test_unit.c` | C, ASan/UBSan | `proto.c`, `sha1.c`, `qr.c` |
| `tests/test_qr_reference.py` | python-qrcode, jsQR | QR output bit for bit, plus decodability |
| `tests/test_integration.py` | Python stdlib | Black-box HTTP/WebSocket against the binary; `--tls` runs it over verified TLS |
| `tests/e2e.mjs` | Playwright | Desktop page + emulated iPhone + Android, real transfers; `--tls` too |

Test-only dependencies: `pip install qrcode`, `cd tests && npm install`, and the `openssl` CLI. Useful patterns already used in the suites:

- **Simulating a phone:**
  - `phoneCtx.setOffline(true)` stops a page from reconnecting;
  - `dropConnection(true)` abandons the socket without closing it, so the server only notices when the device returns;
  - `freezeConnection()` makes the connection die silently.
- **The browser that runs the tests:**
  - It's launched with proxy variables removed. In some environments an HTTP proxy otherwise intercepts the WebSocket traffic.
  - With `--tls`, it trusts the throwaway certificate via `--ignore-certificate-errors-spki-list`. Chrome refuses service workers on untrusted certificates.
- **Background tabs:** test browsers never throttle timers, so throttling is emulated by overriding `setTimeout`. Only meaningful if something else (here a slowly writing receiver) fills the flow-control window.
- **Asserting on toasts:** they disappear after ~4 s, so wait for old ones to go before counting.

Servers started by the tests run with `--quiet`. To debug the server, run it yourself without that flag; it logs session events to stderr.

## Changing things

- **New message type:** handle it in `onMessage()`, and add it to the README's protocol list. The server needs no change unless the server itself must answer.
- **Binary format or other protocol changes:** both devices always run the same page, thanks to the build id. Old pages reload themselves, so there's no compatibility code to write.
- **Anything a reconnect might lose:** decide what `resumeWithPeer()` must replay, and make the receiving side idempotent: duplicate offers, cancels and dones must be ignored.
- **Server changes:** keep `proto.c` free of I/O and unit-test it there. Run the integration suite against an ASan build too:
  ```sh
  cc -fsanitize=address,undefined -DEZX_TLS -Ibuild src/*.c -lssl -lcrypto
  ```
- **Version:** bump `EZX_VERSION` in `src/server.c`. The build id changes on its own whenever the page or service worker changes.
