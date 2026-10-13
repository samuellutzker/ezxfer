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
- **`web/e2e.js`** holds all cryptography, for the optional end-to-end encryption. **`web/qr.js`** draws the page's QR code.

## Build

`make` turns the web files into C headers with `tools/embed.c` (`build/index_html.h`, `build/sw_js.h`, …), then compiles everything into `ezxfer`. OpenSSL is linked when `pkg-config` finds it; `TLS=0` or `TLS=1` overrides that. `src/tls.c` compiles to stubs without `-DEZX_TLS`.

| File | Role |
|---|---|
| `src/main.c` | Option parsing → `server_config` → `server_run()` |
| `src/server.c` | Event loop, connections, sessions, HTTP routes, relay, startup banner |
| `src/proto.c` | Pure parsing: HTTP request head, query strings, WebSocket frames (unit-tested) |
| `src/tls.c` | OpenSSL behind a tiny non-blocking API (`tls_read/write/handshake/pending`) |
| `src/sha1.c` | SHA-1 + Base64 for the WebSocket handshake |
| `src/qr.c` | QR encoder (byte mode, versions 1–40), for the terminal |
| `web/index.html` | The whole app: HTML, CSS and one IIFE script |
| `web/sw.js` | Service worker for streamed downloads |
| `web/e2e.js` | End-to-end encryption: keys, key derivation, sealing and opening |
| `web/qr.js` | `src/qr.c` ported to JavaScript, for the page's QR code |
| `tools/embed.c` | Turns a file into a C byte array at build time |
| `tests/` | Unit, QR reference, integration and browser tests (see [Tests](#tests)) |
| `docs/` | This guide and the README screenshots |

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
   - `/sw.js`, `/e2e.js`, `/qr.js` serve the scripts
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

**Join URL.** `public_origin()` builds the URL in `hello` and in the QR code:
- `--url`, if given;
- otherwise the request's `Host` header, if it looks like a host name (`plausible_host()`);
- otherwise the machine's LAN address from `lan_address()`, which prefers 192.168/16, then 10/8, then 172.16/12. That also applies when the page was opened via `localhost`.

**HTTPS.** HTTPS is enabled by `--cert` (a PEM certificate or chain, leaf first) and `--key`, which defaults to the certificate file. The server accepts TLS 1.2 or newer. A plain request on the TLS port gets a redirect.

For trying HTTPS by hand without mkcert, use a self-signed certificate:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj /CN=ezxfer -addext "subjectAltName=IP:192.168.1.20,DNS:localhost" \
  -keyout key.pem -out cert.pem
```

Browsers make you click through a warning for it. They also behave differently with a certificate they don't trust:
- Safari may still refuse the WebSocket;
- Chrome won't register the service worker, so Android falls back to the in-memory download.

**Build id.** The server hashes (FNV-1a) the served page and scripts at startup. `{{VERSION}}` and `{{BUILD}}` are substituted once, in `render_page()`. `hello` carries the build id; a page with a different one reloads itself. That's why a page left open across an upgrade never speaks an old protocol.

## Protocol

The server relays everything between the two devices. It only looks at the messages it sends or answers itself.

- **From the server:**
  - `hello {session, url, version, build}`
  - `peer {connected, id}`
  - `error {code, message}` (`not_found`, `full`, `busy`)
  - `pong`, the reply to the page's `{"type":"ping"}`
- **Between the devices** (JSON text):
  - `info {name, instance}`
  - `picking {active, what}` (`what` is `open` or `save`)
  - `offer {id, name, size, mime}`
  - `accept {id, offset}`
  - `decline {id}`
  - `cancel {id, from}` (`from` is `sender` or `receiver`)
  - `ack {id, bytes}`
  - `eof {id}`
  - `done {id}`
- **File data:** binary messages, see below.
- **Handshake:** `mode {e2e, check}`, sent by both devices whenever they meet. Nothing else goes to the other device until both agree; see [Encryption](#end-to-end-encryption).

The flows:

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
- **`picking {active, what}`:** a file picker (`open`) or save-location prompt (`save`) is open. The other device shows "Choosing files…" or "Choosing where to save…". A connection drop meanwhile isn't reported for up to 2 minutes (`PICK_GRACE`); any other drop is reported right away.

## End-to-end encryption

Optional, offered only on HTTPS pages (WebCrypto needs a secure context, and without TLS the page itself could be tampered with). It's off by default; the host turns it on per session.

**Key.** 20 characters from a 32-symbol alphabet (100 bits), shown as `XXXXX-XXXXX-XXXXX-XXXXX`. The host's page makes it; it travels in the join link after `#k=` (browsers never send the fragment to a server), so the QR code is drawn by the page (`qr.js`), not the server. A device joining by typed code is asked to type it. Keys are kept in `sessionStorage` per session code, so reloads keep them.

**Crypto** (`e2e.js`, unit-tested in `tests/test_crypto.mjs`, `make test-js`):
- `E2E.channel(key, session, me, peer)` derives one AES-256-GCM key per direction with HKDF-SHA256 (salt `ezxfer e2e v1|<session>`, info `<from id>><to id>`). Non-extractable, kept in a closure. Separate directions mean a relay can't bounce a device's own boxes back to it.
- A box is `iv (12) | ciphertext | tag (16)`, with a random IV each time. The additional data is `msg` for messages and the 12-byte header for file chunks, which ties each chunk to its transfer and offset.
- The key check is the sealed message `{"type":"key-check"}`.
- `seal()` returns an `E2E.Sealed`, a type nothing else can create.

**Handshake.** When the peer appears, each side sends `mode {e2e, check}`: whether it encrypts, plus a key check if it does. Then:
- neither encrypts → plaintext session;
- the peer encrypts and we have no key → the key dialog, which verifies the typed key against the peer's check before using it;
- both encrypt and the peer's check opens with our key → encrypted session;
- otherwise the encrypting side waits ("Waiting for the other device to enter the key"). It never falls back to plaintext.

**On the wire** (all in `index.html`, section *talking to the network*):
- `toServer()` sends only `ping` and `mode`.
- `wire()` sends everything for the other device. In an encrypted session it throws on anything that isn't an `E2E.Sealed`. Messages go as `{"type":"sealed","box":<base64>}`, chunks as header + box.
- `receive()` handles every incoming frame in order. Server messages and `mode` are plaintext; everything else is dropped until the handshake is done, and in an encrypted session unless it opens with the peer's key.

**What it protects.** File contents, names, sizes and all other messages, against the relay and anything between it and the browsers (e.g. a TLS-terminating proxy). The page itself still comes from the server, so this does not protect against a server that serves a modified page. The server can still see timing and approximate sizes, and can drop or delay messages.

## Page (`web/index.html`)

It's one IIFE, in sections marked `// ---------- name ----------`.

**Connection.**
- `connect()` / `socketLost()`: reconnect with backoff to the same session. Running transfers pause meanwhile.
- `wakeUp()`: on returning to the page (visibility, focus, `pageshow`), reconnect or run `checkAlive()`. That's a `ping` the server answers; a socket without an answer within 3 s is replaced. There's also a check after 15 s of silence.
- The client id lives in `sessionStorage`, so a tab the phone reloads gets its session slot back. Transfer ids start at a random value, so a reloaded page can't collide with ids the peer remembers.
- Files picked while disconnected are offered once the peer is back.
- `receive()` takes every incoming frame in order (see [Encryption](#end-to-end-encryption)) and dispatches to `onServerMessage()`, `onMode()`, `onPeerMessage()` or `onChunk()`. Peer messages are sent with `toPeer()`.

**Transfers** are plain objects in `outgoing` (by id) and `incoming` (by `peerId:id`). Their states:

```
outgoing: offered ─▶ sending ─▶ finishing ─▶ done
incoming: offered ─▶ saving ─▶ receiving ─▶ done
          (any active state ─▶ declined | cancelled | failed, via endOut()/endIn())
```

- `OUT_ACTIVE` and `IN_ACTIVE` list the states in which a transfer can still change.
- `paused` is a flag, not a state: the transfer waits for a reconnect (`pauseActive()`, `resumeWithPeer()`).

**Sending.** `pump()` sends one transfer at a time. Each chunk is `new Blob([header, file.slice()])`: the browser reads the file, with no copy in JavaScript. With encryption, the slice is read, sealed and sent as header + box. The loop pauses while 16 MB are unacknowledged (`MAX_INFLIGHT`). It's woken by acks (`kickPump()`), **not by timers**, because browsers throttle timers in background tabs. `onAccepted()` first reads one byte of the file, because an unreadable Blob would make the browser kill the whole WebSocket.

**Receiving.** `acceptIncoming()` picks a writer. All three have the same `write/close/abort` interface:

1. `showSaveFilePicker()`: desktop Chrome/Edge, in a secure context (HTTPS or `localhost`);
2. `streamWriter()`: the service worker, in a secure context that isn't iOS. That means Android and desktop Firefox. iOS is excluded because WebKit doesn't reliably turn such a stream into a download, and a transfer that "completes" without a file would be worse than holding it in memory. If the download doesn't start within 5 s, the page falls back to 3.
3. none: chunks collected in memory, then saved with `download()`. Very large files can exceed what a phone browser allows.

Writes are chained on `t.chain`; acks are sent after each write.

**Service worker** (`web/sw.js`). The page registers a download (name, size, type) and passes a `MessagePort`, then opens `/dl/<random>` in a hidden iframe (no file name in the URL, in case the request reaches the server). The worker answers that request with a streaming `Response` fed through the port. Each chunk is acknowledged only when the download has room, which is how backpressure reaches the sender. The page pings the worker every 10 s while a download is open, to keep it alive. The worker must stay a separate, root-level file: browsers don't register inline service workers, and its scope must cover `/dl/`.

**Rendering.** `render(t)` marks a row dirty; `draw(t)` redraws it at most once per animation frame.

**Other parts:**
- `updateWakeLock()` keeps the screen on while transfers are busy.
- `openFile()`: the "Open" button on received files, for files saved through the dialog (read back with `handle.getFile()`) or held in memory. Only for types the browser shows without running anything from the file (`VIEWABLE`): an opened `blob:` URL has this page's origin, so HTML or SVG could run scripts on it. Streamed downloads can't be opened; the page doesn't learn where they were saved.
- `setPicking()` / `setPeerPicking()` implement the "Choosing files…" and "Choosing where to save…" status:
  - **Start:** the file input's `click`, the desktop save dialog, or the start of a download. On Android, Chrome may ask for a save location there, depending on its settings.
  - **End:** `change` or `cancel`, or focus returning after the picker took it away.
  - **Download prompts:** the page can't know whether one will appear, so `maybeChoosingSaveLocation()` withdraws the announcement after 3 s unless the page was left.
- `updateWakeLock()`: the Wake Lock API needs a secure context. Elsewhere, touch devices get a "keep this screen on" hint instead.
- `window.ezxfer` exposes state (including `encrypted` and `rejected`) and fault injection (`dropConnection`, `freezeConnection`) **for the tests only**.

## Tests

```sh
make test   # everything; the TLS suites too when built with TLS
```

| Suite | Tool | What it covers |
|---|---|---|
| `tests/test_unit.c` | C, ASan/UBSan | `proto.c`, `sha1.c`, `qr.c` |
| `tests/test_qr_reference.py` | python-qrcode, jsQR | QR output bit for bit, plus decodability |
| `tests/test_crypto.mjs` | `node --test` | `e2e.js`: keys, derivation, sealing, tampering, key checks |
| `tests/test_qr_js.mjs` | `node --test` | `qr.js` against the C encoder, module for module, and its SVG |
| `tests/test_integration.py` | Python stdlib | Black-box HTTP/WebSocket against the binary; `--tls` runs it over verified TLS |
| `tests/e2e.mjs` | Playwright | Desktop page + emulated iPhone + Android, real transfers; `--tls` too |

Test-only dependencies: `pip install qrcode`, `cd tests && npm install`, and the `openssl` CLI.

What the suites cover, beyond the basics:
- **Unit:**
  - SHA-1/Base64 vectors, the RFC 6455 examples and all frame-length encodings;
  - unmasking checked against the byte-wise definition at every length and alignment;
  - HTTP and query parsing, the QR capacity table and structure.
- **QR:** about 190 symbols across versions 1–40, all ECC levels and masks, matched module for module against python-qrcode and decoded by jsQR.
- **Integration** (plain and `--tls`):
  - routes and errors;
  - sessions: join, full, not found, client-id takeover, empty-session timeout;
  - relay of text, binary and fragmented messages, and protocol violations;
  - a 64 MB transfer, and backpressure keeping server memory flat;
  - `ping`/`pong`, the build id, the Host-header check and command-line options.
  - **TLS only:** the redirect, untrusted clients, garbage and abandoned handshakes, combined and invalid PEM files.
- **E2E** (plain and `--tls`):
  - QR scan → join; transfers both ways on every save path, with byte-for-byte checks;
  - empty files, multiple files, decline and cancel;
  - streamed downloads on Android;
  - resume after the sender or the receiver drops;
  - choosing files and save locations versus real disconnects;
  - dead-connection detection, phone reloads, unreadable files;
  - wake lock, background-tab throttling;
  - session full or stale, server upgrade and restart, layout.
  - **TLS only, encryption:** every frame each page sends and receives is recorded and searched for file contents, names and the key (a plaintext session is the control); joining by QR and by typed code with a wrong and right key; injected, forged and reflected messages dropped; resume and reload.

Useful patterns already used in the suites:

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

- **New message type:** handle it in `onPeerMessage()` and send it with `toPeer()` (encrypted automatically), and add it to the [protocol list](#protocol). The server needs no change unless the server itself must answer.
- **Binary format or other protocol changes:** both devices always run the same page, thanks to the build id. Old pages reload themselves, so there's no compatibility code to write.
- **Anything a reconnect might lose:** decide what `resumeWithPeer()` must replay, and make the receiving side idempotent: duplicate offers, cancels and dones must be ignored.
- **Server changes:** keep `proto.c` free of I/O and unit-test it there. Run the integration suite against an ASan build too:
  ```sh
  cc -fsanitize=address,undefined -DEZX_TLS -Ibuild src/*.c -lssl -lcrypto
  ```
- **Version:** bump `EZX_VERSION` in `src/server.c`. The build id changes on its own whenever the page or a script changes.
