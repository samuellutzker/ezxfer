# ezxfer

Send files between a computer and a phone (or any two devices) from the browser.
Open the page, scan the QR code, then pick files on either side.

`ezxfer` is a single C program with no required dependencies (libc and POSIX sockets only; OpenSSL optionally, for HTTPS) containing:

- a small HTTP/1.1 server and a WebSocket (RFC 6455) server, with its own SHA-1 and Base64
- a QR code encoder (versions 1–40, all error-correction levels) that serves the code as SVG
- the web app (`web/index.html`) and its service worker (`web/sw.js`), compiled into the binary at build time

| Desktop | Phone | Dark mode |
|---|---|---|
| ![desktop](docs/desktop.png) | ![phone](docs/phone.png) | ![dark](docs/desktop-dark.png) |

## Build & run

```sh
make
./ezxfer            # listens on 0.0.0.0:8080, plain HTTP
```

`make` links OpenSSL when it is installed (detected with `pkg-config`), which makes the `--cert`/`--key` options available. `make TLS=0` builds the fully dependency-free binary instead, and `make TLS=1` requires OpenSSL. `./ezxfer --help` tells you which kind of build you have.

On startup it prints the URLs and a QR code in the terminal. Open `http://localhost:8080` on the computer and scan the QR code shown on the page with your phone.

```
Options:
  -p, --port PORT    TCP port to listen on (default 8080)
  -b, --bind ADDR    IPv4 address to bind (default 0.0.0.0)
  -u, --url URL      public base URL encoded in QR codes
                     (default: http://<lan-ip>:<port>)
  -w, --web FILE     serve FILE as the page template instead of the
                     built-in one ({{VERSION}} and {{BUILD}} are
                     substituted)
  -c, --cert FILE    serve HTTPS using this PEM certificate (chain);
                     without it the server speaks plain HTTP
  -k, --key FILE     PEM private key for --cert (default: read the
                     key from the --cert file)
  -t, --session-timeout SECONDS
                     how long a session waits for its devices to
                     reconnect after both dropped (default 120)
      --no-qr        don't print a QR code in the terminal
      --full-qr      print the terminal QR code at full height, for
                     terminals that show gaps in the compact one
                     (e.g. macOS Terminal)
  -q, --quiet        no banner or logging
  -h, --help         show this help
```

Builds with gcc or clang on Linux and macOS.

## HTTPS (optional)

The server speaks plain HTTP unless you give it a certificate:

```sh
./ezxfer --cert cert.pem --key key.pem
```

With a certificate, the same port serves HTTPS and secure WebSockets (WSS), and the QR code links to `https://…`. A plain `http://` request to that port is redirected to `https://`. `--cert` takes a PEM certificate or a full chain (leaf first). If the private key is in the same file, `--key` can be omitted. The server only accepts TLS 1.2 or newer.

HTTPS also gives desktop Chrome/Edge on other machines the native **Save as** dialog, because that needs a secure context.

**Getting a certificate the phone trusts.** The phone checks the certificate against the address in the QR code, which is usually your LAN IP. There are two options:

- **Recommended: [mkcert](https://github.com/FiloSottile/mkcert).** It creates a local certificate authority. Install its root CA on the phone once (on iOS, also enable it under *Settings → General → About → Certificate Trust Settings*). After that, certificates it issues are trusted without warnings:
  ```sh
  mkcert -install
  mkcert -cert-file cert.pem -key-file key.pem 192.168.1.20 localhost 127.0.0.1
  ```
- **Quick self-signed certificate.** Browsers show a warning that you have to click through on each device:
  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj /CN=ezxfer -addext "subjectAltName=IP:192.168.1.20,DNS:localhost" \
    -keyout key.pem -out cert.pem
  ```
  Some browsers, notably Safari, may refuse the WebSocket connection to an untrusted certificate even after you accept the page warning. If the page loads but never says "Waiting for device", use a trusted certificate instead (mkcert).

  Chrome also refuses service workers on a site whose certificate it doesn't trust, so with a clicked-through self-signed certificate, downloads on Android fall back to collecting the file in memory. Large downloads to an Android phone need a trusted certificate (mkcert).

## How it works

1. Opening the page connects a WebSocket to `/ws`. The server creates a **session** with a random 6-character code and replies with a join URL like `http://192.168.1.20:8080/?s=K7PQ2M`. The page shows that URL as a QR code (`/qr.svg?d=…`).
2. The phone opens that URL and connects to `/ws?s=K7PQ2M`, which joins the session. Each session holds two devices; a third is turned away. You can also type the code into the **Join** box on another computer.
3. Picking files sends an *offer* (name, size, type) to the peer, where it shows up with **Accept / Decline**. When the receiver accepts and picks where to save, the sender starts streaming. The data goes as 1 MB binary WebSocket messages, and the server relays each one to the other device unchanged. Each message is a slice of the file that the browser reads itself, so no copy is made in JavaScript.
4. Where to save:
   - Browsers with the File System Access API (desktop Chrome/Edge over `localhost` or HTTPS) show a native **Save as** dialog and write straight to disk.
   - Otherwise, on HTTPS (or `localhost`), Android and desktop Firefox stream the file into the browser's normal download through a small service worker (`/sw.js`), so it never sits in memory. The worker answers a hidden `/dl/…` request with a streaming response that the page feeds chunk by chunk. Backpressure from the download reaches all the way back to the sender.
   - Everywhere else (plain-HTTP LAN pages, and iOS, whose WebKit doesn't reliably download such streams), the file is collected in memory and then handed to the browser's normal download.

Files are relayed, never stored. Flow control works end to end:
- The sender keeps at most 16 MB that the receiver hasn't acknowledged yet. It's woken by the acknowledgements, not by a timer, because browsers throttle timers in background tabs. A tab sending in the background therefore keeps full speed.
- The server stops reading from a sender once that sender's peer has more than 4 MB of output queued.

Memory therefore stays bounded however large the file is.

**Dropped connections resume.** Each page has a random client id, which it sends when connecting.
- If a device's connection drops, for example a phone that loses Wi-Fi or locks its screen, transfers on both sides pause.
- When the device reconnects with the same id, it takes back its slot in the session. This works even if the server hasn't yet noticed that the old connection died.
- The receiver then tells the sender which byte to continue from.
- Every data chunk carries its byte offset, so chunks left over from before the drop are discarded instead of being written in the wrong place.
- If both devices drop, the session waits `--session-timeout` seconds (default 120) for them to return.
- Phones often drop the connection while a page is in the background, for example while the file picker is open. To cope with that:
  - Coming back to the page triggers a quick check with the server, and a connection that died silently is replaced within about 3 seconds. The page also checks every 15 seconds of silence.
  - Files picked while the connection is down are offered as soon as the other device is back.
  - The client id is kept per tab (`sessionStorage`). If the phone reloads the tab, the page gets its place in the session back instead of ending up in a new session.
- **Choosing files or a save location** (on any device): the page tells the other device when its file picker opens and closes, and the other device's status shows **"Choosing files…"**. The same goes for choosing where to save a received file, shown as **"Choosing where to save…"**: the desktop "Save as" dialog, or the prompt Chrome on Android may show when a download starts. The page can't know whether that prompt will appear, so it withdraws the announcement after 3 seconds unless the page was left in the meantime. Phones often lose the connection while the picker is open. During that time a drop is expected, so it isn't reported as a disconnect, and the transfer screen stays up. When the phone is back, everything continues quietly. If it hasn't returned after 2 minutes, it counts as disconnected. A connection lost any other way, for example when the app goes to the background, is reported right away as "Device disconnected".
- Reloading the page still starts its transfers over, because the browser can't keep the selected file or the partial download across a reload. Transfers in progress end with "The other device reloaded the page" instead of waiting forever.
- When the server is upgraded, pages left open would reconnect and keep running the old code. The server therefore sends a build id, and a page that's older than the server reloads itself once.

### Protocol

The server only relays messages between the two devices of a session. Apart from the messages below, it doesn't look at their content.

- **From the server:**
  - `hello {session, url, version, build}`
  - `peer {connected, id}`
  - `error {code, message}` (`not_found`, `full`, `busy`)
  - `pong`, the reply to the page's `ping` liveness check
- **Between the devices** (JSON text):
  - `info {name, instance}`
  - `picking {active, what}` (`what` is `open` when choosing files to send, `save` when choosing a save location)
  - `offer {id, name, size, mime}`
  - `accept {id, offset}`
  - `decline {id}`
  - `cancel {id, from}`
  - `ack {id, bytes}`
  - `eof {id}`
  - `done {id}`
- **File data:** binary messages, each made of a 12-byte header (`u32` transfer id, `u64` byte offset, big-endian) followed by up to 1 MB of the file.

The join URL uses the address the page was opened with. If that was `localhost`, the server substitutes the machine's LAN IPv4 address. Use `--url` when running behind a reverse proxy or NAT.

### Limits and notes

- By default traffic is plain HTTP; use `--cert`/`--key` to encrypt it (see above). Behind a TLS reverse proxy such as Caddy or nginx, run ezxfer without a certificate and pass `--url https://…`.
- Anyone who knows a session's code can join it while it has a free slot. Codes are random (32⁶ ≈ 10⁹ combinations), and a session is full once two devices are connected.
- While a transfer is running, the page keeps the screen on with the Screen Wake Lock API, because phones drop network connections when the screen locks. Browsers only offer this on HTTPS (or `localhost`); elsewhere, phones show a hint to keep the screen on.
- Only the in-memory route (plain HTTP, or iOS) holds the whole file in memory until the transfer completes. That is fine for photos and videos, but very large files (several GB) on a phone may hit browser limits. To receive big files on an Android phone, run with `--cert`/`--key` so downloads are streamed.

## Layout

For how the pieces fit together, see the [developer guide](docs/DEVELOPMENT.md).

```
src/main.c      command line parsing
src/server.c    poll() event loop, HTTP routes, sessions, WebSocket relay
src/proto.c     HTTP request parser, query decoding, WebSocket framing
src/tls.c       optional OpenSSL wrapper (stubs when built with TLS=0)
src/sha1.c      SHA-1 + Base64 (WebSocket handshake)
src/qr.c        QR code encoder + SVG output
web/index.html  the page (HTML, CSS and JavaScript in one file)
web/sw.js       service worker that streams received files into downloads
tools/embed.c   turns the web files into C headers at build time
tests/          unit, QR reference, integration and browser tests
docs/           developer guide, screenshots
```

## Tests

```sh
make test-unit          # C unit tests under ASan/UBSan
make test-qr            # QR output vs. python-qrcode, bit for bit, plus jsQR decoding
make test-integration   # black-box HTTP/WebSocket tests (Python stdlib only)
make test-e2e           # real Chromium pages: desktop, emulated iPhone and Android phone
make test-integration-tls test-e2e-tls   # the same two suites over HTTPS/WSS
make test               # all of the above (TLS suites when built with TLS)
```

The TLS suites also need the `openssl` command to generate a throwaway certificate. The test-only dependencies are `pip install qrcode` and `cd tests && npm install` (Playwright, jsQR). The program itself has no dependencies.

What is covered:

- **Unit:** SHA-1/Base64 test vectors, the RFC 6455 handshake and framing examples, all payload-length encodings, protocol-error handling, HTTP parsing, query decoding, and the QR capacity table, structure and SVG output.
- **QR:** about 190 symbols across versions 1–40, all ECC levels and all masks, matched module for module against python-qrcode and decoded by jsQR.
- **Integration:**
  - routes and error statuses
  - session create/join/full/not-found, peer leave and rejoin
  - client ids: a reconnecting device takes back its slot, a different one is refused; empty sessions wait for `--session-timeout`
  - the server-side `ping`/`pong`, the build id, and Host headers that are ignored when implausible
  - unmasking (done 8 bytes at a time) checked against the byte-wise definition at every length and alignment, in the unit tests
  - relay of text, binary and fragmented messages; ping/pong; protocol violations
  - a 64 MB transfer with integrity check
  - backpressure: a stalled receiver throttles the sender and server memory stays flat
  - command-line options and the terminal QR code
- **TLS:** the integration and browser suites run in full over HTTPS/WSS, with the client verifying the certificate. Extra TLS tests cover:
  - the http→https redirect and the negotiated protocol version
  - clients that don't trust the certificate, garbage and abandoned handshakes
  - a combined certificate+key PEM file
  - mismatched or invalid PEM files, which are refused at startup
- **E2E:**
  - the page's QR code scans to the join URL, and an emulated iPhone joins with it
  - transfers in both directions, using both save paths, with byte-for-byte checks
  - empty files, several files at once, decline, cancel from either side
  - streamed downloads to an Android phone through the service worker
  - resuming after the receiver or the sender loses its connection mid-transfer
  - "Choosing files…" while the picker is open, versus a real disconnect being reported
  - "Choosing where to save…" for the desktop save dialog and for a phone's download prompt (including a connection drop meanwhile), and its withdrawal when no prompt appears
  - files picked while disconnected, a silently dead connection being replaced, a phone reload (with and without a transfer running)
  - the screen wake lock, and the hint where it's unsupported
  - a sender whose timers are throttled as in a background tab keeps full speed
  - a file deleted before or during a transfer fails cleanly with "Could not read file"
  - disconnect and rejoin, joining by typed code, a third device being refused, a stale link
  - a page left open across a server upgrade reloading itself, reconnecting after a server restart, and the responsive layout
