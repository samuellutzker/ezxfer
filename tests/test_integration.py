#!/usr/bin/env python3
"""Black-box integration tests for the ezxfer server (Python stdlib only).

Usage: python3 tests/test_integration.py ./ezxfer [--tls]

With --tls every test runs over HTTPS/WSS against a freshly generated
self-signed certificate (verified by the client), plus TLS-specific tests.
"""
import base64
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./ezxfer")
TLS = "--tls" in sys.argv[2:]
SCHEME = "https" if TLS else "http"
CERT_DIR = tempfile.mkdtemp(prefix="ezxfer-cert-")
CERT, KEY = os.path.join(CERT_DIR, "cert.pem"), os.path.join(CERT_DIR, "key.pem")
PASSED = []
SESSION_TIMEOUT = 2  # seconds an empty session is kept in the main test server


def make_cert(cert, key, cn="ezxfer-test"):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "2", "-subj", f"/CN={cn}",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)


def cert_args():
    return ["--cert", CERT, "--key", KEY] if TLS else []


def connect(port, timeout=5, tls=None):
    """TCP connection to the server, wrapped in verified TLS in --tls mode."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if TLS if tls is None else tls:
        ctx = ssl.create_default_context(cafile=CERT)
        s = ctx.wrap_socket(s, server_hostname="127.0.0.1")
    return s


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, *args):
        self.port = free_port()
        self.proc = subprocess.Popen([BIN, "-p", str(self.port), "--quiet", *cert_args(), *args])
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def rss_kb(self):
        with open(f"/proc/{self.proc.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        return 0

    def stop(self):
        self.proc.terminate()
        try:
            return self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise


def http(port, raw: bytes, timeout=5, tls=None):
    s = connect(port, timeout, tls)
    s.sendall(raw)
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except (ConnectionResetError, ssl.SSLError):
            break
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else 0
    headers = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
    return status, headers, body


def get(port, path, host="127.0.0.1"):
    return http(port, f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())


class WS:
    """Minimal RFC 6455 client."""

    def __init__(self, port, path="/ws", host=None, timeout=10):
        self.sock = connect(port, timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        host = host or f"127.0.0.1:{port}"
        self.sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            self.buf += chunk
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 101"), head
        expect = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert b"Sec-WebSocket-Accept: " + expect in head, head
        self.lock = threading.Lock()

    @staticmethod
    def frame(opcode, payload: bytes, fin=True, mask=True):
        b0 = (0x80 if fin else 0) | opcode
        n = len(payload)
        if n < 126:
            hdr = struct.pack("!BB", b0, (0x80 if mask else 0) | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", b0, (0x80 if mask else 0) | 126, n)
        else:
            hdr = struct.pack("!BBQ", b0, (0x80 if mask else 0) | 127, n)
        if not mask:
            return hdr + payload
        key = os.urandom(4)
        # fast XOR via int arithmetic
        k = (key * (n // 4 + 1))[:n]
        masked = (int.from_bytes(payload, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big") if n else b""
        return hdr + key + masked

    def send_raw(self, data: bytes):
        with self.lock:
            self.sock.sendall(data)

    def send_text(self, s):
        self.send_raw(self.frame(0x1, s.encode() if isinstance(s, str) else s))

    def send_json(self, obj):
        self.send_text(json.dumps(obj))

    def send_bin(self, b):
        self.send_raw(self.frame(0x2, b))

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk

    def recv_frame(self):
        self._need(2)
        b0, b1 = self.buf[0], self.buf[1]
        assert not (b1 & 0x80), "server frames must not be masked"
        n, off = b1 & 0x7F, 2
        if n == 126:
            self._need(4)
            n, off = struct.unpack("!H", self.buf[2:4])[0], 4
        elif n == 127:
            self._need(10)
            n, off = struct.unpack("!Q", self.buf[2:10])[0], 10
        self._need(off + n)
        payload = self.buf[off:off + n]
        self.buf = self.buf[off + n:]
        return b0 >> 7, b0 & 0x0F, payload

    def recv(self):
        """Next data message as (opcode, payload); returns (8, payload) on close."""
        while True:
            fin, op, payload = self.recv_frame()
            if op in (0x1, 0x2, 0x8):
                return op, payload
            if op == 0x9:
                self.send_raw(self.frame(0xA, payload))

    def recv_json(self):
        op, payload = self.recv()
        assert op == 0x1, (op, payload[:100])
        return json.loads(payload)

    def expect_closed(self):
        try:
            op, payload = self.recv()
            while op != 0x8:
                op, payload = self.recv()
            return struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
        except (ConnectionError, OSError):
            return None

    def close(self):
        try:
            self.send_raw(self.frame(0x8, struct.pack("!H", 1000)))
        except OSError:
            pass
        self.sock.close()


def test(fn):
    def run(*a):
        fn(*a)
        PASSED.append(fn.__name__)
        print(f"  ok  {fn.__name__}")
    return run


def pair(port):
    a = WS(port)
    ha = a.recv_json()
    assert ha["type"] == "hello" and len(ha["session"]) == 6, ha
    b = WS(port, "/ws?s=" + ha["session"].lower())  # codes are case-insensitive
    hb = b.recv_json()
    assert hb["type"] == "hello" and hb["session"] == ha["session"], hb
    assert a.recv_json() == {"type": "peer", "connected": True}
    assert b.recv_json() == {"type": "peer", "connected": True}
    return a, b, ha["session"]


# ---------------------------------------------------------------- HTTP

@test
def http_index(srv):
    st, h, body = get(srv.port, "/")
    assert st == 200 and h["content-type"].startswith("text/html")
    assert int(h["content-length"]) == len(body)
    assert b"<title>ezxfer</title>" in body and b"{{VERSION}}" not in body and b"v1.0.0" in body
    assert get(srv.port, "/index.html")[0] == 200


@test
def http_head(srv):
    st, h, body = http(srv.port, b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert st == 200 and body == b"" and int(h["content-length"]) > 1000


@test
def http_qr_svg(srv):
    st, h, body = get(srv.port, "/qr.svg?d=" + "http%3A%2F%2F10.0.0.2%3A8080%2F%3Fs%3DABCDEF")
    assert st == 200 and h["content-type"] == "image/svg+xml"
    assert body.startswith(b"<?xml") and body.rstrip().endswith(b"</svg>")
    assert get(srv.port, "/qr.svg")[0] == 400
    assert get(srv.port, "/qr.svg?d=")[0] == 400
    assert get(srv.port, "/qr.svg?d=" + "x" * 1100)[0] == 400  # longer than the decode buffer


@test
def http_errors(srv):
    assert get(srv.port, "/nope")[0] == 404
    assert get(srv.port, "/../../etc/passwd")[0] == 404
    assert http(srv.port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")[0] == 405
    assert http(srv.port, b"BLAH\r\n\r\n")[0] == 400
    assert http(srv.port, b"GET / HTTP/1.1\r\nX: " + b"a" * 20000 + b"\r\n\r\n")[0] == 431
    assert get(srv.port, "/health")[2] == b"ok\n"
    # plain GET on /ws without upgrade headers
    assert get(srv.port, "/ws")[0] == 400
    st, h, _ = http(srv.port, b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                              b"Sec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 8\r\n\r\n")
    assert st == 426 and h["sec-websocket-version"] == "13"


@test
def http_split_request(srv):
    """A request arriving in small pieces is still parsed."""
    s = connect(srv.port)
    for piece in [b"GE", b"T /hea", b"lth HTTP/1.1\r\n", b"Host: x\r\n", b"\r\n"]:
        s.sendall(piece)
        time.sleep(0.05)
    data = b""
    while chunk := s.recv(4096):
        data += chunk
    assert data.startswith(b"HTTP/1.1 200") and data.endswith(b"ok\n")


# ---------------------------------------------------------------- WebSocket sessions

@test
def ws_hello_url(srv):
    a = WS(srv.port)
    h = a.recv_json()
    # localhost Host header -> URL uses a LAN address and the server port
    assert h["url"].startswith(SCHEME + "://") and h["url"].endswith(f":{srv.port}/?s={h['session']}"), h
    a.close()
    # A non-local Host header is kept as-is (e.g. reached via LAN IP or hostname)
    b = WS(srv.port, host="my-pc.lan:1234")
    assert b.recv_json()["url"].startswith(SCHEME + "://my-pc.lan:1234/?s=")
    b.close()


@test
def ws_relay_text_and_binary(srv):
    a, b, _ = pair(srv.port)
    a.send_json({"type": "offer", "id": 1, "name": "ü.txt", "size": 3})
    assert b.recv_json() == {"type": "offer", "id": 1, "name": "ü.txt", "size": 3}
    b.send_json({"type": "accept", "id": 1})
    assert a.recv_json() == {"type": "accept", "id": 1}
    for size in (0, 1, 125, 126, 65535, 65536, 1 << 20):
        payload = os.urandom(size)
        a.send_bin(payload)
        assert b.recv() == (0x2, payload)
        b.send_bin(payload)
        assert a.recv() == (0x2, payload)
    a.close()
    b.close()


@test
def ws_fragmented_message(srv):
    a, b, _ = pair(srv.port)
    a.send_raw(WS.frame(0x2, b"abc", fin=False) + WS.frame(0x0, b"def", fin=False))
    a.send_raw(WS.frame(0x9, b"ping!"))  # control frame interleaved in a fragmented message
    a.send_raw(WS.frame(0x0, b"ghi", fin=True))
    fin, op, payload = a.recv_frame()
    assert (op, payload) == (0xA, b"ping!")
    assert b.recv() == (0x2, b"abcdefghi")
    a.close()
    b.close()


@test
def ws_ping_pong(srv):
    a = WS(srv.port)
    a.recv_json()
    a.send_raw(WS.frame(0x9, b"hi"))
    assert a.recv_frame()[1:] == (0xA, b"hi")
    a.close()


@test
def ws_session_full_and_missing(srv):
    a, b, code = pair(srv.port)
    c = WS(srv.port, "/ws?s=" + code)
    err = c.recv_json()
    assert err["type"] == "error" and err["code"] == "full", err
    assert c.expect_closed() == 4009
    d = WS(srv.port, "/ws?s=ZZZZZZ")
    err = d.recv_json()
    assert err["type"] == "error" and err["code"] == "not_found", err
    assert d.expect_closed() == 4004
    a.close()
    b.close()


@test
def ws_peer_leave_and_rejoin(srv):
    a, b, code = pair(srv.port)
    a.close()
    assert b.recv_json() == {"type": "peer", "connected": False}
    # session survives while one device remains; a new device can join it
    c = WS(srv.port, "/ws?s=" + code)
    assert c.recv_json()["session"] == code
    assert c.recv_json() == {"type": "peer", "connected": True}
    assert b.recv_json() == {"type": "peer", "connected": True}
    c.send_text("hello again")
    assert b.recv() == (0x1, b"hello again")
    # abrupt disconnect (no close frame) is noticed too
    c.sock.close()
    assert b.recv_json() == {"type": "peer", "connected": False}
    b.close()
    # last device gone -> the session waits a while for devices to come back...
    time.sleep(0.3)
    d = WS(srv.port, "/ws?s=" + code)
    assert d.recv_json()["session"] == code
    d.close()
    # ...and is destroyed once the timeout has passed with nobody in it
    time.sleep(SESSION_TIMEOUT + 1.5)
    e = WS(srv.port, "/ws?s=" + code)
    assert e.recv_json()["code"] == "not_found"
    e.sock.close()


@test
def ws_peer_ids_and_reconnect_takeover(srv):
    a = WS(srv.port, "/ws?c=device-A")
    code = a.recv_json()["session"]
    b = WS(srv.port, f"/ws?s={code}&c=device_B")
    b.recv_json()
    assert a.recv_json() == {"type": "peer", "connected": True, "id": "device_B"}
    assert b.recv_json() == {"type": "peer", "connected": True, "id": "device-A"}
    # B's network dies silently; the server still thinks the old connection is alive.
    # A different device is refused, but B coming back takes over its own slot.
    c = WS(srv.port, f"/ws?s={code}&c=someone-else")
    assert c.recv_json()["code"] == "full"
    c.sock.close()
    b2 = WS(srv.port, f"/ws?s={code}&c=device_B")
    assert b2.recv_json()["session"] == code
    assert b2.recv_json() == {"type": "peer", "connected": True, "id": "device-A"}
    assert a.recv_json() == {"type": "peer", "connected": False}
    assert a.recv_json() == {"type": "peer", "connected": True, "id": "device_B"}
    assert b.expect_closed() == 4001  # the stale connection is closed
    a.send_text("resumed")
    assert b2.recv() == (0x1, b"resumed")
    # invalid ids are ignored (treated as no id)
    a.close()
    assert b2.recv_json() == {"type": "peer", "connected": False}
    d = WS(srv.port, f"/ws?s={code}&c=bad%22id")
    d.recv_json()
    assert b2.recv_json() == {"type": "peer", "connected": True}
    for x in (b2, d):
        x.close()


@test
def ws_both_drop_and_return(srv):
    """Both devices lose their connection; the session waits for them."""
    a = WS(srv.port, "/ws?c=one")
    code = a.recv_json()["session"]
    b = WS(srv.port, f"/ws?s={code}&c=two")
    b.recv_json(), a.recv_json(), b.recv_json()
    a.sock.close()
    b.sock.close()
    time.sleep(0.3)
    a2 = WS(srv.port, f"/ws?s={code}&c=one")
    assert a2.recv_json()["session"] == code
    b2 = WS(srv.port, f"/ws?s={code}&c=two")
    assert b2.recv_json()["session"] == code
    assert a2.recv_json()["id"] == "two" and b2.recv_json()["id"] == "one"
    a2.close()
    b2.close()


@test
def ws_sessions_isolated(srv):
    pairs = [pair(srv.port) for _ in range(20)]
    codes = {p[2] for p in pairs}
    assert len(codes) == 20
    for i, (a, b, _) in enumerate(pairs):
        a.send_text(f"msg {i}")
    for i, (a, b, _) in enumerate(pairs):
        assert b.recv() == (0x1, f"msg {i}".encode())
    for a, b, _ in pairs:
        a.close()
        b.close()


@test
def ws_message_without_peer_is_dropped(srv):
    a = WS(srv.port)
    a.recv_json()
    a.send_text("nobody here")
    a.send_raw(WS.frame(0x9, b"x"))
    assert a.recv_frame()[1:] == (0xA, b"x")  # still alive
    a.close()


@test
def ws_protocol_errors(srv):
    a, b, _ = pair(srv.port)
    a.send_raw(WS.frame(0x1, b"unmasked", mask=False))
    assert a.expect_closed() == 1002
    assert b.recv_json() == {"type": "peer", "connected": False}
    b.close()

    a, b, _ = pair(srv.port)
    a.send_raw(WS.frame(0x0, b"orphan continuation"))
    assert a.expect_closed() == 1002
    b.close()

    a, b, _ = pair(srv.port)
    # announce a 5 MB frame (over the 4 MB limit); only the header is needed
    a.send_raw(struct.pack("!BBQ", 0x82, 0x80 | 127, 5 << 20) + b"\0\0\0\0")
    assert a.expect_closed() == 1009
    b.close()


@test
def ws_bulk_transfer_integrity(srv):
    """Stream 64 MB in 256 KB chunks while the receiver reads concurrently."""
    a, b, _ = pair(srv.port)
    total, chunk = 64 << 20, 256 << 10
    sent_hash, recv_hash = hashlib.sha256(), hashlib.sha256()
    received = [0]

    def reader():
        while received[0] < total:
            op, payload = b.recv()
            assert op == 0x2
            recv_hash.update(payload)
            received[0] += len(payload)

    t = threading.Thread(target=reader)
    t.start()
    start = time.time()
    seed = os.urandom(chunk)
    for i in range(total // chunk):
        data = seed[i % 256:] + seed[:i % 256]
        sent_hash.update(data)
        a.send_bin(data)
    t.join(60)
    elapsed = time.time() - start
    assert received[0] == total and sent_hash.digest() == recv_hash.digest()
    print(f"        64 MB relayed in {elapsed:.2f}s ({total / elapsed / 1e6:.0f} MB/s)")
    a.close()
    b.close()


@test
def ws_backpressure_bounds_memory(srv):
    """A slow receiver must not make the server buffer the whole stream."""
    a, b, _ = pair(srv.port)
    b.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 10)
    base = srv.rss_kb()
    total, chunk = 96 << 20, 256 << 10
    data = os.urandom(chunk)
    sent = [0]

    def writer():
        try:
            for _ in range(total // chunk):
                a.send_bin(data)
                sent[0] += chunk
        except OSError:
            pass

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    time.sleep(2.0)  # receiver is not reading at all
    stalled_at = sent[0]
    peak = srv.rss_kb()
    assert stalled_at < total, "sender should have been throttled"
    assert peak - base < 40 * 1024, f"server grew by {(peak - base) / 1024:.0f} MB"
    got = 0
    while got < total:
        op, payload = b.recv()
        assert op == 0x2 and payload == data
        got += len(payload)
    t.join(10)
    print(f"        sender stalled at {stalled_at >> 20} MB, server RSS grew {(peak - base) / 1024:.1f} MB")
    a.close()
    b.close()


@test
def ws_pipelined_frames_after_handshake(srv):
    """Frames sent in the same packet as the handshake are not lost."""
    a = WS(srv.port)
    code = a.recv_json()["session"]
    s = connect(srv.port)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET /ws?s={code} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
              + WS.frame(0x1, b"early bird"))
    assert a.recv_json() == {"type": "peer", "connected": True}
    assert a.recv() == (0x1, b"early bird")
    s.close()
    a.close()


# ---------------------------------------------------------------- TLS only

@test
def tls_plain_http_is_redirected(srv):
    st, h, body = http(srv.port, b"GET /some/path?s=ABC HTTP/1.1\r\nHost: my-pc.lan:8443\r\n\r\n", tls=False)
    assert st == 301 and h["location"] == "https://my-pc.lan:8443/some/path?s=ABC", (st, h)


@test
def tls_handshake_details(srv):
    s = connect(srv.port)
    assert s.version() in ("TLSv1.2", "TLSv1.3"), s.version()
    s.close()
    # a client that doesn't trust the certificate fails, and the server carries on
    raw = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        ssl.create_default_context().wrap_socket(raw, server_hostname="127.0.0.1")
        raise AssertionError("untrusted certificate was accepted")
    except ssl.SSLCertVerificationError:
        pass
    assert get(srv.port, "/health")[2] == b"ok\n"


@test
def tls_garbage_and_abandoned_handshakes(srv):
    bad = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    bad.sendall(b"\x16\x03\x01\x00\x05hello-not-a-client-hello")
    # the server may send a TLS alert first, but must close the connection
    while True:
        try:
            if not bad.recv(4096):
                break
        except ConnectionResetError:
            break
    stalled = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    stalled.sendall(b"\x16")  # starts a handshake and never finishes it
    # neither blocks the server
    a, b, _ = pair(srv.port)
    a.send_text("still serving")
    assert b.recv() == (0x1, b"still serving")
    for x in (bad, stalled, a, b):
        x.close()


# ---------------------------------------------------------------- options

def test_options():
    srv = Server("--url", "https://files.example.com/")
    try:
        a = WS(srv.port)
        h = a.recv_json()
        assert h["url"] == f"https://files.example.com/?s={h['session']}", h
        a.close()
    finally:
        srv.stop()
    PASSED.append("option_url")
    print("  ok  option_url")

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write("<p>custom template {{VERSION}} / {{VERSION}}</p>")
    srv = Server("--web", f.name)
    try:
        st, _, body = get(srv.port, "/")
        assert st == 200 and body == b"<p>custom template 1.0.0 / 1.0.0</p>", body
    finally:
        srv.stop()
        os.unlink(f.name)
    PASSED.append("option_web_template")
    print("  ok  option_web_template")

    r = subprocess.run([BIN, "--web", "/nonexistent.html", "-q"], capture_output=True)
    assert r.returncode != 0
    r = subprocess.run([BIN, "--port", "99999"], capture_output=True)
    assert r.returncode == 2
    r = subprocess.run([BIN, "--help"], capture_output=True)
    assert r.returncode == 0 and b"Usage" in r.stderr
    r = subprocess.run([BIN, "--session-timeout", "-1"], capture_output=True)
    assert r.returncode == 2
    r = subprocess.run([BIN, "--key", KEY], capture_output=True)
    assert r.returncode == 2 and b"--key requires --cert" in r.stderr
    r = subprocess.run([BIN, "--cert", "/nonexistent.pem", "-q"], capture_output=True)
    assert r.returncode == 1 and r.stderr, r.stderr
    PASSED.append("option_validation")
    print("  ok  option_validation")

    # startup banner with terminal QR code
    port = free_port()
    p = subprocess.Popen([BIN, "-p", str(port), *cert_args()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)
    p.terminate()
    out, _ = p.communicate(timeout=5)
    assert b"Open on other devices" in out and "█".encode() in out
    assert f"Open on this computer:  {SCHEME}://localhost:{port}/".encode() in out, out
    assert p.returncode == 0
    PASSED.append("startup_banner_qr")
    print("  ok  startup_banner_qr")

    if TLS:
        test_tls_options()


def test_tls_options():
    # certificate and key in one PEM file, passed with --cert only
    combined = os.path.join(CERT_DIR, "combined.pem")
    with open(combined, "w") as f:
        f.write(open(CERT).read() + open(KEY).read())
    port = free_port()
    p = subprocess.Popen([BIN, "-p", str(port), "-q", "--cert", combined])
    try:
        time.sleep(0.3)
        assert get(port, "/health")[2] == b"ok\n"
    finally:
        p.terminate()
        p.wait(5)
    PASSED.append("tls_combined_pem")
    print("  ok  tls_combined_pem")

    # a key that doesn't belong to the certificate is refused at startup
    other_cert, other_key = os.path.join(CERT_DIR, "o.pem"), os.path.join(CERT_DIR, "ok.pem")
    make_cert(other_cert, other_key, "other")
    r = subprocess.run([BIN, "-q", "--cert", CERT, "--key", other_key], capture_output=True)
    assert r.returncode == 1 and b"does not match" in r.stderr, r.stderr
    r = subprocess.run([BIN, "-q", "--cert", KEY, "--key", KEY], capture_output=True)  # not a certificate
    assert r.returncode == 1 and b"cannot load certificate" in r.stderr, r.stderr
    PASSED.append("tls_bad_pem_files")
    print("  ok  tls_bad_pem_files")


def main():
    make_cert(CERT, KEY)
    print(f"mode: {'HTTPS/WSS' if TLS else 'plain HTTP/WS'}")
    srv = Server("--session-timeout", str(SESSION_TIMEOUT))
    prefixes = ("http_", "ws_", "tls_") if TLS else ("http_", "ws_")
    try:
        for name, fn in list(globals().items()):
            if name.startswith(prefixes) and callable(fn):
                fn(srv)
        assert srv.proc.poll() is None, "server crashed"
        assert srv.stop() == 0, "server did not exit cleanly on SIGTERM"
    except Exception:
        srv.proc.kill()
        raise
    test_options()
    shutil.rmtree(CERT_DIR, ignore_errors=True)
    print(f"integration tests ({'TLS' if TLS else 'plain'}): {len(PASSED)} passed")


if __name__ == "__main__":
    main()
