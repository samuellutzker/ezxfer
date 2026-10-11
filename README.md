# ezxfer

Send files between a computer and a phone (or any two devices) from the browser.
Open the page, scan the QR code, then pick files on either side.

`ezxfer` is a single, dependency-free C program (libc and POSIX sockets only) containing:

- a small HTTP/1.1 server and a WebSocket (RFC 6455) server, with its own SHA-1 and Base64
- a QR code encoder (versions 1–40, all error-correction levels) that serves the code as SVG
- the web app (`web/index.html`), compiled into the binary at build time

| Desktop | Phone | Dark mode |
|---|---|---|
| ![desktop](docs/desktop.png) | ![phone](docs/phone.png) | ![dark](docs/desktop-dark.png) |

## Build & run

```sh
make
./ezxfer            # listens on 0.0.0.0:8080
```

On startup it prints the URLs and a QR code in the terminal. Open `http://localhost:8080` on the computer and scan the QR code shown on the page with your phone.

```
Options:
  -p, --port PORT    TCP port to listen on (default 8080)
  -b, --bind ADDR    IPv4 address to bind (default 0.0.0.0)
  -u, --url URL      public base URL encoded in QR codes
                     (default: http://<lan-ip>:<port>)
  -w, --web FILE     serve FILE as the page template instead of the
                     built-in one ({{VERSION}} is substituted)
      --no-qr        don't print a QR code in the terminal
  -q, --quiet        no banner or logging
```

Builds with gcc or clang on Linux and macOS.

## How it works

1. Opening the page connects a WebSocket to `/ws`. The server creates a **session** with a random 6-character code and replies with a join URL like `http://192.168.1.20:8080/?s=K7PQ2M`. The page shows that URL as a QR code (`/qr.svg?d=…`).
2. The phone opens that URL and connects to `/ws?s=K7PQ2M`, which joins the session. Each session holds two devices; a third is turned away. You can also type the code into the **Join** box on another computer.
3. Picking files sends an *offer* (name, size, type) to the peer, where it shows up with **Accept / Decline**. When the receiver accepts and picks where to save, the sender starts streaming. The data goes as 256 KB binary WebSocket messages, and the server relays each one to the other device unchanged.
4. Where to save:
   - Browsers with the File System Access API (desktop Chrome/Edge over `localhost` or HTTPS) show a native **Save as** dialog and write straight to disk.
   - Other browsers (phones, plain-HTTP LAN pages) collect the file in memory and hand it to the browser's normal download.

Files are relayed, never stored. Flow control works end to end:
- The sender limits its WebSocket buffer and the amount of data the receiver hasn't acknowledged yet.
- The server stops reading from a sender once that sender's peer has more than 4 MB of output queued.

Memory therefore stays bounded however large the file is.

The join URL uses the address the page was opened with. If that was `localhost`, the server substitutes the machine's LAN IPv4 address. Use `--url` when running behind a reverse proxy or NAT.

### Limits and notes

- There is no TLS: traffic is plain HTTP on your LAN. To use it across the internet, put it behind a TLS reverse proxy (e.g. Caddy or nginx) and pass `--url https://…`.
- Anyone who knows a session's code can join it while it has a free slot. Codes are random (32⁶ ≈ 10⁹ combinations), and a session is full once two devices are connected.
- Without the File System Access API, the receiving browser holds the whole file in memory until the transfer completes. That is fine for photos and videos, but very large files (several GB) on a phone may hit browser limits.

## Layout

```
src/main.c      command line parsing
src/server.c    poll() event loop, HTTP routes, sessions, WebSocket relay
src/proto.c     HTTP request parser, query decoding, WebSocket framing
src/sha1.c      SHA-1 + Base64 (WebSocket handshake)
src/qr.c        QR code encoder + SVG output
web/index.html  the frontend (embedded via tools/embed.c into build/index_html.h)
tests/          unit, QR reference, integration and browser tests
```

## Tests

```sh
make test-unit          # C unit tests under ASan/UBSan
make test-qr            # QR output vs. python-qrcode, bit for bit, plus jsQR decoding
make test-integration   # black-box HTTP/WebSocket tests (Python stdlib only)
make test-e2e           # two real Chromium pages (desktop + emulated iPhone)
make test               # all of the above
```

The test-only dependencies are `pip install qrcode` and `cd tests && npm install` (Playwright, jsQR). The program itself has no dependencies.

What is covered:

- **Unit:** SHA-1/Base64 test vectors, the RFC 6455 handshake and framing examples, all payload-length encodings, protocol-error handling, HTTP parsing, query decoding, and the QR capacity table, structure and SVG output.
- **QR:** about 190 symbols across versions 1–40, all ECC levels and all masks, matched module for module against python-qrcode and decoded by jsQR.
- **Integration:**
  - routes and error statuses
  - session create/join/full/not-found, peer leave and rejoin
  - relay of text, binary and fragmented messages; ping/pong; protocol violations
  - a 64 MB transfer with integrity check
  - backpressure: a stalled receiver throttles the sender and server memory stays flat
  - command-line options and the terminal QR code
- **E2E:**
  - the page's QR code scans to the join URL, and an emulated iPhone joins with it
  - transfers in both directions, using both save paths, with byte-for-byte checks
  - empty files, several files at once, decline, cancel from either side
  - disconnect and rejoin, joining by typed code, a third device being refused, a stale link
  - reconnecting after a server restart, and the responsive layout
