# ezxfer

Send files between a computer and a phone, or any two devices, right from the browser. Open the page, scan the QR code, pick files. No app, no account, no cloud.

| Desktop | Phone | Dark mode |
|---|---|---|
| ![desktop](docs/desktop.png) | ![phone](docs/phone.png) | ![dark](docs/desktop-dark.png) |

## Features

- **Pair by QR code** or by typing a 6-character session code.
- **Both directions:** each device can send. Files show up on the other side with Accept / Decline.
- **Large files:** data streams straight through and is never stored.
- **Robust on phones:** transfers resume after a dropped connection, and the screen stays on while transferring.
- **Optional HTTPS** with your own certificate, and with it optional **end-to-end encryption**: the server only relays data it can't read.
- **A single small C program:** the web app is built in. It needs no dependencies, or only OpenSSL if you want HTTPS.
- Responsive, with light and dark themes.

## Build & run

```sh
make
./ezxfer
```

Open `http://localhost:8080` on the computer and scan the QR code with your phone. The server also prints the address for other devices.

It builds with gcc or clang on Linux and macOS. `make` uses OpenSSL if it's installed; `make TLS=0` builds without it.

```
Options:
  -p, --port PORT    TCP port to listen on (default 8080)
  -b, --bind ADDR    IPv4 address to bind (default 0.0.0.0)
  -u, --url URL      public base URL for join links and QR codes
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
  -q, --quiet        no banner or logging
  -h, --help         show this help
```

## HTTPS

```sh
./ezxfer --cert cert.pem --key key.pem
```

HTTPS encrypts transfers and lets phones stream large downloads to disk and keep the screen on. Plain `http://` requests to the same port are redirected.

Phones need to **trust** the certificate. Otherwise some browsers refuse the connection or the streamed downloads. The easiest way is [mkcert](https://github.com/FiloSottile/mkcert): install its root certificate on the phone once, then create a certificate for your computer's LAN address:

```sh
mkcert -cert-file cert.pem -key-file key.pem 192.168.1.20 localhost
```

Behind a reverse proxy that handles TLS (Caddy, nginx), run ezxfer without a certificate and pass `--url https://your.host`.

## End-to-end encryption

On HTTPS pages, tick **End-to-end encryption** before the other device connects. Files and file names are then encrypted in the browser (AES-256-GCM) with a key the server never sees.
- **Scanning the QR code or opening the link** joins with the key; it's part of the link.
- **Typing the session code** asks for the key shown under the QR code.

The page itself is still served by ezxfer, so this protects against the relay and anything in between (e.g. a proxy), not against a modified server.

## Good to know

- Anyone with the session code can join while a slot is free. A session holds two devices.
- Without HTTPS, a received file is held in memory until it's complete. That's fine for photos and videos, but files of several GB may exceed what a phone or tablet allows; the page warns before you accept one. With HTTPS, current browsers save it to disk as it arrives.
- Reloading the page cancels its running transfers.

## Development

```sh
make test   # unit, QR, integration and browser tests
```

The tests need a few test-only tools: `pip install qrcode`, `cd tests && npm install` (Playwright, jsQR) and the `openssl` command. The [developer guide](docs/DEVELOPMENT.md) explains the architecture, the protocol and the test suites.
