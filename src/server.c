#define _GNU_SOURCE
#include "server.h"
#include "proto.h"
#include "qr.h"
#include "tls.h"
#include "index_html.h"
#include "sw_js.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* SIGPIPE is ignored globally */
#endif

#define EZX_VERSION "1.0.0"

#define MAX_CONNS 512
#define MAX_SESSIONS 256
#define HTTP_MAX_HEAD 16384
#define WS_MAX_MSG ((size_t)4 << 20)       /* largest relayed message */
#define OUT_HIGH_WATER ((size_t)4 << 20)   /* stop reading from a peer above this */
#define READ_CHUNK 65536
#define HTTP_TIMEOUT 15
#define WS_PING_INTERVAL 20
#define WS_TIMEOUT 60
#define CODE_LEN 6

static const char CODE_ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

typedef struct {
    uint8_t *d;
    size_t len, cap, off; /* off: consumed prefix (output buffers only) */
} buffer;

struct session;

/* TLS connection states (plain-HTTP servers use TS_PLAIN throughout) */
enum { TS_PLAIN, TS_DETECT, TS_HANDSHAKE, TS_READY };

typedef struct conn {
    int fd;
    int tls_state;
    int tls_want;       /* poll events the TLS handshake is waiting for */
    int redirect_https; /* plain HTTP on a TLS port: answer with a redirect */
    tls_conn *tls;
    int is_ws;
    int closing; /* close once the output buffer has been flushed */
    buffer in, out, frag;
    int frag_op;
    struct session *sess;
    time_t last_rx, last_ping, created;
    char host[256];
    char addr[64];
    char cid[65]; /* client id chosen by the page; lets a device reclaim its slot */
} conn;

typedef struct session {
    char code[CODE_LEN + 1];
    conn *peer[2];
    time_t empty_since; /* both devices gone: kept for cfg->session_timeout seconds */
} session;

static const server_config *g_cfg;
static conn *g_conns[MAX_CONNS];
static session *g_sessions[MAX_SESSIONS];
static volatile sig_atomic_t g_stop;
static int g_tls; /* serving HTTPS */

static void logf_(const char *fmt, ...)
{
    if (g_cfg && g_cfg->quiet)
        return;
    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof ts, "%H:%M:%S", localtime(&now));
    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ---------------- buffers ---------------- */

static int buf_reserve(buffer *b, size_t extra)
{
    if (b->len + extra <= b->cap)
        return 0;
    if (b->off > 0 && b->off >= b->len / 2) { /* compact before growing */
        memmove(b->d, b->d + b->off, b->len - b->off);
        b->len -= b->off;
        b->off = 0;
        if (b->len + extra <= b->cap)
            return 0;
    }
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->len + extra)
        nc *= 2;
    uint8_t *nd = realloc(b->d, nc);
    if (!nd)
        return -1;
    b->d = nd;
    b->cap = nc;
    return 0;
}

static int buf_append(buffer *b, const void *data, size_t n)
{
    if (buf_reserve(b, n) < 0)
        return -1;
    memcpy(b->d + b->len, data, n);
    b->len += n;
    return 0;
}

static void buf_free(buffer *b)
{
    free(b->d);
    memset(b, 0, sizeof *b);
}

static size_t out_pending(const conn *c) { return c ? c->out.len - c->out.off : 0; }

/* ---------------- helpers ---------------- */

static void random_bytes(uint8_t *p, size_t n)
{
    static int fd = -2;
    if (fd == -2)
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t got = 0;
    while (fd >= 0 && got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    if (got < n) { /* extremely unlikely fallback */
        static unsigned seed;
        if (!seed)
            seed = (unsigned)time(NULL) ^ (unsigned)getpid();
        for (; got < n; got++)
            p[got] = (uint8_t)(rand_r(&seed) >> 7);
    }
}

void lan_address(char *out, unsigned outsz)
{
    snprintf(out, outsz, "127.0.0.1");
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0)
        return;
    int best = 0;
    for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK))
            continue;
        uint32_t a = ntohl(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
        /* Prefer typical home/office LAN ranges over e.g. docker bridges */
        int score = 1;
        if ((a >> 16) == 0xC0A8)
            score = 4; /* 192.168/16 */
        else if ((a >> 24) == 10)
            score = 3; /* 10/8 */
        else if ((a >> 20) == 0xAC1)
            score = 2; /* 172.16/12 */
        if (score > best) {
            best = score;
            inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, out, outsz);
        }
    }
    freeifaddrs(ifa);
}

static int is_local_host(const char *h)
{
    return !*h || strcmp(h, "localhost") == 0 || strncmp(h, "127.", 4) == 0 ||
           strcmp(h, "[::1]") == 0 || strcmp(h, "0.0.0.0") == 0;
}

/* Origin (scheme://host:port) that other devices should use to reach us. */
static void public_origin(const char *host_header, char *out, size_t outsz)
{
    if (g_cfg->base_url && *g_cfg->base_url) {
        snprintf(out, outsz, "%s", g_cfg->base_url);
        size_t l = strlen(out);
        while (l > 0 && out[l - 1] == '/')
            out[--l] = '\0';
        return;
    }
    char host[256];
    snprintf(host, sizeof host, "%s", host_header);
    /* strip port, keeping IPv6 brackets */
    char *colon = host[0] == '[' ? strstr(host, "]:") : strrchr(host, ':');
    if (colon)
        colon[host[0] == '[' ? 1 : 0] = '\0';
    if (is_local_host(host)) {
        char ip[64];
        if (g_cfg->bind_addr && strcmp(g_cfg->bind_addr, "0.0.0.0") != 0 &&
            !is_local_host(g_cfg->bind_addr))
            snprintf(ip, sizeof ip, "%s", g_cfg->bind_addr);
        else
            lan_address(ip, sizeof ip);
        snprintf(out, outsz, "%s://%s:%d", g_tls ? "https" : "http", ip, g_cfg->port);
    } else {
        snprintf(out, outsz, "%s://%s", g_tls ? "https" : "http", host_header);
    }
}

/* ---------------- sessions ---------------- */

static session *session_find(const char *code)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i] && strcmp(g_sessions[i]->code, code) == 0)
            return g_sessions[i];
    return NULL;
}

static void session_destroy(session *s);

static int session_empty(const session *s) { return !s->peer[0] && !s->peer[1]; }

static session *session_create(void)
{
    int slot = -1, oldest = -1;
    for (int i = 0; i < MAX_SESSIONS && slot < 0; i++) {
        if (!g_sessions[i])
            slot = i;
        else if (session_empty(g_sessions[i]) &&
                 (oldest < 0 || g_sessions[i]->empty_since < g_sessions[oldest]->empty_since))
            oldest = i;
    }
    if (slot < 0 && oldest >= 0) { /* all slots used: recycle the longest-abandoned one */
        session_destroy(g_sessions[oldest]);
        slot = oldest;
    }
    if (slot < 0)
        return NULL;
    session *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    do {
        uint8_t r[CODE_LEN];
        random_bytes(r, sizeof r);
        for (int i = 0; i < CODE_LEN; i++)
            s->code[i] = CODE_ALPHABET[r[i] % (sizeof CODE_ALPHABET - 1)];
        s->code[CODE_LEN] = '\0';
    } while (session_find(s->code));
    g_sessions[slot] = s;
    return s;
}

static void session_destroy(session *s)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i] == s)
            g_sessions[i] = NULL;
    logf_("session %s closed", s->code);
    free(s);
}

static conn *session_peer(const conn *c)
{
    if (!c->sess)
        return NULL;
    return c->sess->peer[0] == c ? c->sess->peer[1] : c->sess->peer[0];
}

/* ---------------- output ---------------- */

static void ws_send(conn *c, int opcode, const void *data, size_t len)
{
    if (!c || c->closing)
        return;
    uint8_t hdr[10];
    size_t hl = ws_frame_header(hdr, opcode, len);
    if (buf_reserve(&c->out, hl + len) < 0) {
        c->closing = 1;
        return;
    }
    buf_append(&c->out, hdr, hl);
    buf_append(&c->out, data, len);
}

static void ws_send_text(conn *c, const char *s) { ws_send(c, WS_OP_TEXT, s, strlen(s)); }

static void ws_close(conn *c, unsigned code, const char *reason)
{
    uint8_t p[125];
    size_t rl = strlen(reason);
    if (rl > sizeof p - 2)
        rl = sizeof p - 2;
    p[0] = (uint8_t)(code >> 8);
    p[1] = (uint8_t)code;
    memcpy(p + 2, reason, rl);
    ws_send(c, WS_OP_CLOSE, p, rl + 2);
    c->closing = 1;
}

static void http_respond(conn *c, int status, const char *reason, const char *ctype,
                         const void *body, size_t len, const char *extra)
{
    char hdr[1024];
    int hl = snprintf(hdr, sizeof hdr,
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Cache-Control: no-store\r\n"
                      "X-Content-Type-Options: nosniff\r\n"
                      "Referrer-Policy: no-referrer\r\n"
                      "Connection: close\r\n"
                      "%s\r\n",
                      status, reason, ctype, len, extra ? extra : "");
    if (buf_append(&c->out, hdr, (size_t)hl) < 0 || buf_append(&c->out, body, len) < 0)
        c->out.len = c->out.off = 0;
    c->closing = 1;
}

static void http_error(conn *c, int status, const char *reason)
{
    char body[128];
    int n = snprintf(body, sizeof body, "%d %s\n", status, reason);
    http_respond(c, status, reason, "text/plain; charset=utf-8", body, (size_t)n, NULL);
}

/* ---------------- connection lifecycle ---------------- */

/* Removes c from its session and tells the other device. An empty session is
 * kept for a while so devices that lost their connection can come back. */
static void session_detach(conn *c)
{
    session *s = c->sess;
    if (!s)
        return;
    conn *peer = session_peer(c);
    for (int i = 0; i < 2; i++)
        if (s->peer[i] == c)
            s->peer[i] = NULL;
    c->sess = NULL;
    if (peer) {
        ws_send_text(peer, "{\"type\":\"peer\",\"connected\":false}");
        logf_("session %s: peer %s left", s->code, c->addr);
    } else {
        s->empty_since = time(NULL);
        logf_("session %s: empty, kept for %ds", s->code, g_cfg->session_timeout);
    }
}

static void conn_free(conn *c)
{
    for (int i = 0; i < MAX_CONNS; i++)
        if (g_conns[i] == c)
            g_conns[i] = NULL;
    session_detach(c);
    tls_free(c->tls);
    close(c->fd);
    buf_free(&c->in);
    buf_free(&c->out);
    buf_free(&c->frag);
    free(c);
}

/* ---------------- HTTP handling ---------------- */

static char *g_template; /* contents of --web file, if any */
static size_t g_template_len;

static void serve_index(conn *c)
{
    const char *src = g_template ? g_template : (const char *)index_html;
    size_t len = g_template ? g_template_len : index_html_len;
    /* Template substitution: {{VERSION}} */
    static const char ph[] = "{{VERSION}}";
    buffer b = {0};
    size_t i = 0;
    while (i < len) {
        const char *hit = memmem(src + i, len - i, ph, sizeof ph - 1);
        size_t chunk = hit ? (size_t)(hit - (src + i)) : len - i;
        buf_append(&b, src + i, chunk);
        i += chunk;
        if (hit) {
            buf_append(&b, EZX_VERSION, strlen(EZX_VERSION));
            i += sizeof ph - 1;
        }
    }
    http_respond(c, 200, "OK", "text/html; charset=utf-8", b.d, b.len,
                 "Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; "
                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                 "connect-src 'self' ws: wss:\r\n");
    buf_free(&b);
}

static void serve_qr(conn *c, const http_request *req)
{
    char data[1024];
    int n = query_param(req->query, "d", data, sizeof data);
    if (n <= 0) {
        http_error(c, 400, "Bad Request");
        return;
    }
    static qr_code qr;
    if (qr_encode((const uint8_t *)data, (size_t)n, QR_ECC_M, 1, -1, &qr) != 0) {
        http_error(c, 414, "URI Too Long");
        return;
    }
    char *svg = qr_to_svg(&qr, 4);
    if (!svg) {
        http_error(c, 500, "Internal Server Error");
        return;
    }
    http_respond(c, 200, "OK", "image/svg+xml", svg, strlen(svg), NULL);
    free(svg);
}

/* Client ids are opaque tokens: [A-Za-z0-9_-], at most 64 characters. */
static int valid_client_id(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') ||
              *s == '-' || *s == '_'))
            return 0;
    return 1;
}

/* Tells `to` that `other` is connected, including other's client id if any. */
static void send_peer_connected(conn *to, const conn *other)
{
    char msg[160];
    if (other->cid[0])
        snprintf(msg, sizeof msg, "{\"type\":\"peer\",\"connected\":true,\"id\":\"%s\"}",
                 other->cid);
    else
        snprintf(msg, sizeof msg, "{\"type\":\"peer\",\"connected\":true}");
    ws_send_text(to, msg);
}

static void normalize_code(char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z')
            *s = (char)(*s - 'a' + 'A');
}

static void ws_upgrade(conn *c, const http_request *req)
{
    if (!req->upgrade_ws || !req->connection_up || !req->ws_key[0]) {
        http_error(c, 400, "Bad Request");
        return;
    }
    if (req->ws_version != 13) {
        http_respond(c, 426, "Upgrade Required", "text/plain", "", 0,
                     "Sec-WebSocket-Version: 13\r\n");
        return;
    }
    char accept[29];
    ws_accept_key(req->ws_key, accept);
    char resp[256];
    int rl = snprintf(resp, sizeof resp,
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n",
                      accept);
    buf_append(&c->out, resp, (size_t)rl);
    c->is_ws = 1;
    c->last_rx = c->last_ping = time(NULL);
    snprintf(c->host, sizeof c->host, "%s", req->host);

    char code[32] = "";
    query_param(req->query, "s", code, sizeof code);
    normalize_code(code);
    char cid[sizeof c->cid] = "";
    if (query_param(req->query, "c", cid, sizeof cid) > 0 && valid_client_id(cid))
        snprintf(c->cid, sizeof c->cid, "%s", cid);

    session *s;
    int slot;
    if (code[0]) {
        s = session_find(code);
        if (!s) {
            ws_send_text(c, "{\"type\":\"error\",\"code\":\"not_found\","
                            "\"message\":\"Session not found or expired\"}");
            ws_close(c, 4004, "not found");
            return;
        }
        /* The same device reconnecting replaces its old connection, which may
         * not have noticed yet that the network went away. */
        slot = -1;
        for (int i = 0; i < 2 && slot < 0; i++)
            if (s->peer[i] && c->cid[0] && strcmp(s->peer[i]->cid, c->cid) == 0) {
                conn *old = s->peer[i];
                logf_("session %s: %s reconnected, replacing its old connection", s->code, c->addr);
                session_detach(old);
                ws_close(old, 4001, "replaced");
                slot = i;
            }
        if (slot < 0)
            slot = !s->peer[0] ? 0 : !s->peer[1] ? 1 : -1;
        if (slot < 0) {
            ws_send_text(c, "{\"type\":\"error\",\"code\":\"full\","
                            "\"message\":\"This session already has two devices\"}");
            ws_close(c, 4009, "full");
            return;
        }
    } else {
        s = session_create();
        if (!s) {
            ws_send_text(c, "{\"type\":\"error\",\"code\":\"busy\","
                            "\"message\":\"Server is busy, try again later\"}");
            ws_close(c, 1013, "busy");
            return;
        }
        slot = 0;
        logf_("session %s created by %s", s->code, c->addr);
    }
    s->peer[slot] = c;
    c->sess = s;

    char origin[320], msg[700];
    public_origin(req->host, origin, sizeof origin);
    snprintf(msg, sizeof msg,
             "{\"type\":\"hello\",\"session\":\"%s\",\"url\":\"%s/?s=%s\",\"version\":\"%s\"}",
             s->code, origin, s->code, EZX_VERSION);
    ws_send_text(c, msg);

    conn *peer = session_peer(c);
    if (peer) {
        logf_("session %s: %s joined, peers connected", s->code, c->addr);
        send_peer_connected(c, peer);
        send_peer_connected(peer, c);
    }
}

static void handle_http(conn *c)
{
    if (c->closing)
        return;
    http_request req;
    int hl = http_parse_request((const char *)c->in.d, c->in.len, &req);
    if (hl > HTTP_MAX_HEAD || (hl == 0 && c->in.len > HTTP_MAX_HEAD)) {
        http_error(c, 431, "Request Header Fields Too Large");
        return;
    }
    if (hl == 0)
        return;
    if (hl < 0) {
        http_error(c, 400, "Bad Request");
        return;
    }
    /* keep any bytes after the head (a WebSocket client may pipeline frames) */
    memmove(c->in.d, c->in.d + hl, c->in.len - (size_t)hl);
    c->in.len -= (size_t)hl;

    int is_get = strcmp(req.method, "GET") == 0, is_head = strcmp(req.method, "HEAD") == 0;
    if (c->redirect_https) {
        char origin[320], loc[2000];
        if (req.host[0])
            snprintf(origin, sizeof origin, "https://%s", req.host);
        else
            public_origin("", origin, sizeof origin);
        snprintf(loc, sizeof loc, "Location: %s%s%s%s\r\n", origin, req.path,
                 req.query[0] ? "?" : "", req.query);
        http_respond(c, 301, "Moved Permanently", "text/plain", "Use HTTPS\n", 10, loc);
        return;
    }
    if (!is_get && !is_head) {
        http_error(c, 405, "Method Not Allowed");
        return;
    }
    if (strcmp(req.path, "/") == 0 || strcmp(req.path, "/index.html") == 0)
        serve_index(c);
    else if (strcmp(req.path, "/qr.svg") == 0)
        serve_qr(c, &req);
    else if (strcmp(req.path, "/sw.js") == 0)
        http_respond(c, 200, "OK", "text/javascript; charset=utf-8", sw_js, sw_js_len, NULL);
    else if (strcmp(req.path, "/ws") == 0 && is_get)
        ws_upgrade(c, &req);
    else if (strcmp(req.path, "/health") == 0)
        http_respond(c, 200, "OK", "text/plain", "ok\n", 3, NULL);
    else
        http_error(c, 404, "Not Found");

    if (is_head && !c->is_ws) { /* drop the body, keep the headers */
        uint8_t *sep = memmem(c->out.d + c->out.off, out_pending(c), "\r\n\r\n", 4);
        if (sep)
            c->out.len = (size_t)(sep - c->out.d) + 4;
    }
}

/* ---------------- WebSocket handling ---------------- */

static void relay(conn *c, int opcode, const uint8_t *data, size_t len)
{
    conn *peer = session_peer(c);
    if (peer && peer->is_ws)
        ws_send(peer, opcode, data, len);
}

static void handle_ws(conn *c)
{
    size_t pos = 0;
    while (!c->closing && pos < c->in.len) {
        ws_frame f;
        long n = ws_parse_frame(c->in.d + pos, c->in.len - pos, WS_MAX_MSG, 1, &f);
        if (n == 0)
            break;
        if (n < 0) {
            ws_close(c, n == WS_ERR_TOO_BIG ? 1009 : 1002,
                     n == WS_ERR_TOO_BIG ? "message too big" : "protocol error");
            break;
        }
        pos += (size_t)n;
        c->last_rx = time(NULL);

        switch (f.opcode) {
        case WS_OP_TEXT:
        case WS_OP_BINARY:
            if (c->frag_op) {
                ws_close(c, 1002, "expected continuation");
                break;
            }
            if (f.fin) {
                relay(c, f.opcode, f.payload, (size_t)f.len);
            } else {
                c->frag_op = f.opcode;
                c->frag.len = 0;
                buf_append(&c->frag, f.payload, (size_t)f.len);
            }
            break;
        case WS_OP_CONT:
            if (!c->frag_op) {
                ws_close(c, 1002, "unexpected continuation");
                break;
            }
            if (c->frag.len + f.len > WS_MAX_MSG) {
                ws_close(c, 1009, "message too big");
                break;
            }
            buf_append(&c->frag, f.payload, (size_t)f.len);
            if (f.fin) {
                relay(c, c->frag_op, c->frag.d, c->frag.len);
                c->frag_op = 0;
                c->frag.len = 0;
            }
            break;
        case WS_OP_PING:
            ws_send(c, WS_OP_PONG, f.payload, (size_t)f.len);
            break;
        case WS_OP_PONG:
            break;
        case WS_OP_CLOSE:
            ws_send(c, WS_OP_CLOSE, f.payload, f.len >= 2 ? 2 : 0);
            c->closing = 1;
            break;
        }
    }
    memmove(c->in.d, c->in.d + pos, c->in.len - pos);
    c->in.len -= pos;
}

/* ---------------- socket I/O ---------------- */

/* > 0 bytes, 0 = would block, -1 = closed or failed */
static long io_read(conn *c, void *buf, size_t n)
{
    if (c->tls)
        return tls_read(c->tls, buf, n);
    ssize_t r = recv(c->fd, buf, n, 0);
    if (r > 0)
        return r;
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    return -1;
}

static long io_write(conn *c, const void *buf, size_t n)
{
    if (c->tls)
        return tls_write(c->tls, buf, n);
    ssize_t w = send(c->fd, buf, n, MSG_NOSIGNAL);
    if (w >= 0)
        return w;
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
}

/* Advances a TLS connection that is still being set up. Returns -1 to drop,
 * 0 while waiting, 1 once application data can flow. */
static int tls_progress(conn *c)
{
    if (c->tls_state == TS_DETECT) {
        /* A TLS ClientHello starts with 0x16; anything else is plain HTTP. */
        uint8_t b;
        ssize_t r = recv(c->fd, &b, 1, MSG_PEEK);
        if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            return -1;
        if (r < 0)
            return 0;
        if (b != 0x16) {
            c->tls_state = TS_PLAIN;
            c->redirect_https = 1;
            return 1;
        }
        c->tls = tls_new(c->fd);
        if (!c->tls)
            return -1;
        c->tls_state = TS_HANDSHAKE;
    }
    if (c->tls_state == TS_HANDSHAKE) {
        int want = TLS_WANT_READ;
        int r = tls_handshake(c->tls, &want);
        if (r < 0)
            return -1;
        if (r == 0) {
            c->tls_want = want;
            return 0;
        }
        c->tls_state = TS_READY;
    }
    return 1;
}

/* Returns -1 if the connection should be dropped. */
static int conn_read(conn *c)
{
    for (int iter = 0; iter < 4; iter++) {
        if (buf_reserve(&c->in, READ_CHUNK) < 0)
            return -1;
        long r = io_read(c, c->in.d + c->in.len, READ_CHUNK);
        if (r <= 0)
            return r;
        c->in.len += (size_t)r;
        if (!c->is_ws)
            handle_http(c);
        if (c->is_ws) /* also handles frames pipelined right after the upgrade */
            handle_ws(c);
        if (c->closing)
            return 0;
        /* honour back-pressure: stop reading once the peer is saturated */
        if (out_pending(session_peer(c)) > OUT_HIGH_WATER)
            return 0;
        if ((size_t)r < READ_CHUNK && !tls_pending(c->tls))
            return 0;
    }
    return 0;
}

static int conn_flush(conn *c)
{
    while (out_pending(c) > 0) {
        long w = io_write(c, c->out.d + c->out.off, out_pending(c));
        if (w <= 0)
            return (int)w;
        c->out.off += (size_t)w;
    }
    c->out.len = c->out.off = 0;
    /* Free large idle buffers so a finished transfer doesn't pin memory. */
    if (c->out.cap > (1u << 20)) {
        free(c->out.d);
        c->out.d = NULL;
        c->out.cap = 0;
    }
    return c->closing ? -1 : 0;
}

static void accept_new(int lfd)
{
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t sl = sizeof sa;
        int fd = accept(lfd, (struct sockaddr *)&sa, &sl);
        if (fd < 0)
            return;
        int slot = -1;
        for (int i = 0; i < MAX_CONNS && slot < 0; i++)
            if (!g_conns[i])
                slot = i;
        conn *c = slot >= 0 ? calloc(1, sizeof *c) : NULL;
        if (!c) {
            close(fd);
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        c->fd = fd;
        c->tls_state = g_tls ? TS_DETECT : TS_PLAIN;
        c->created = c->last_rx = time(NULL);
        if (sa.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr, c->addr, sizeof c->addr);
        else if (sa.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr, c->addr,
                      sizeof c->addr);
        g_conns[slot] = c;
    }
}

static void housekeeping(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session *s = g_sessions[i];
        if (s && session_empty(s) && now - s->empty_since >= g_cfg->session_timeout)
            session_destroy(s);
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        conn *c = g_conns[i];
        if (!c)
            continue;
        if (!c->is_ws) {
            if (now - c->created > HTTP_TIMEOUT)
                conn_free(c);
            continue;
        }
        if (now - c->last_rx > WS_TIMEOUT) {
            logf_("connection %s timed out", c->addr);
            conn_free(c);
        } else if (now - c->last_rx >= WS_PING_INTERVAL &&
                   now - c->last_ping >= WS_PING_INTERVAL) {
            ws_send(c, WS_OP_PING, "", 0);
            c->last_ping = now;
        }
    }
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int open_listener(const server_config *cfg)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)cfg->port);
    if (inet_pton(AF_INET, cfg->bind_addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "invalid bind address: %s\n", cfg->bind_addr);
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, 64) < 0) {
        fprintf(stderr, "cannot listen on %s:%d: %s\n", cfg->bind_addr, cfg->port,
                strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void print_banner(const server_config *cfg)
{
    char origin[320];
    public_origin("", origin, sizeof origin);
    printf("\n  ezxfer %s - browser file transfer\n\n", EZX_VERSION);
    printf("  Open on this computer:  %s://localhost:%d/\n", g_tls ? "https" : "http", cfg->port);
    printf("  Open on other devices:  %s/\n\n", origin);
    if (cfg->print_qr) {
        char url[340];
        snprintf(url, sizeof url, "%s/", origin);
        static qr_code qr;
        if (qr_encode((const uint8_t *)url, strlen(url), QR_ECC_L, 0, -1, &qr) == 0) {
            const int border = 2;
            if (cfg->print_qr == 1) {
                /* compact (default): two modules per line using half-block glyphs.
                 * Some terminals (e.g. macOS Terminal) leave gaps between the
                 * lines; --full-qr avoids that. */
                for (int y = -border; y < qr.size + border; y += 2) {
                    printf("  \033[30;107m");
                    for (int x = -border; x < qr.size + border; x++) {
                        int top = qr_module(&qr, x, y), bot = qr_module(&qr, x, y + 1);
                        fputs(top && bot ? "\xe2\x96\x88" : top ? "\xe2\x96\x80"
                                                        : bot ? "\xe2\x96\x84" : " ",
                              stdout);
                    }
                    printf("\033[0m\n");
                }
            } else {
                /* --full-qr: each module is two spaces with a black or white
                 * background. Backgrounds fill the whole cell including the line
                 * spacing, so this renders without gaps in every terminal, at
                 * twice the height. */
                for (int y = -border; y < qr.size + border; y++) {
                    int cur = -1;
                    printf("  ");
                    for (int x = -border; x < qr.size + border; x++) {
                        int dark = qr_module(&qr, x, y);
                        if (dark != cur)
                            fputs(dark ? "\033[40m" : "\033[107m", stdout);
                        cur = dark;
                        fputs("  ", stdout);
                    }
                    printf("\033[0m\n");
                }
            }
            printf("\n");
        }
    }
    fflush(stdout);
}

static int load_template(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    buffer b = {0};
    char tmp[8192];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_append(&b, tmp, n);
    fclose(f);
    g_template = (char *)b.d;
    g_template_len = b.len;
    return 0;
}

int server_run(const server_config *cfg)
{
    g_cfg = cfg;
    if (cfg->web_file && load_template(cfg->web_file) < 0)
        return 1;
    if (cfg->tls_cert) {
        char err[512];
        if (tls_init(cfg->tls_cert, cfg->tls_key, err, sizeof err) < 0) {
            fprintf(stderr, "%s\n", err);
            return 1;
        }
        g_tls = 1;
    }
    int lfd = open_listener(cfg);
    if (lfd < 0)
        return 1;

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (!cfg->quiet)
        print_banner(cfg);

    static struct pollfd pfd[MAX_CONNS + 1];
    static conn *pconn[MAX_CONNS + 1];
    time_t last_hk = time(NULL);

    static uint8_t force_read[MAX_CONNS + 1];
    while (!g_stop) {
        int n = 0, timeout = 1000;
        pfd[n].fd = lfd;
        pfd[n].events = POLLIN;
        pconn[n++] = NULL;
        for (int i = 0; i < MAX_CONNS; i++) {
            conn *c = g_conns[i];
            if (!c)
                continue;
            short ev = 0;
            force_read[n] = 0;
            if (c->tls_state == TS_DETECT) {
                ev = POLLIN;
            } else if (c->tls_state == TS_HANDSHAKE) {
                ev = c->tls_want == TLS_WANT_WRITE ? POLLOUT : POLLIN;
            } else {
                if (!c->closing && out_pending(session_peer(c)) <= OUT_HIGH_WATER) {
                    ev |= POLLIN;
                    /* decrypted data already inside OpenSSL won't wake poll() */
                    if (tls_pending(c->tls)) {
                        force_read[n] = 1;
                        timeout = 0;
                    }
                }
                if (out_pending(c) > 0 || c->closing)
                    ev |= POLLOUT;
            }
            pfd[n].fd = c->fd;
            pfd[n].events = ev;
            pfd[n].revents = 0;
            pconn[n++] = c;
        }

        int r = poll(pfd, (nfds_t)n, timeout);
        if (r < 0 && errno != EINTR) {
            perror("poll");
            break;
        }
        if (r >= 0) {
            if (pfd[0].revents & POLLIN)
                accept_new(lfd);
            for (int i = 1; i < n; i++) {
                conn *c = pconn[i];
                short re = pfd[i].revents;
                if (force_read[i])
                    re |= POLLIN;
                if (!re)
                    continue;
                int drop = 0;
                if (c->tls_state == TS_DETECT || c->tls_state == TS_HANDSHAKE) {
                    int st = tls_progress(c);
                    if (st < 0) {
                        conn_free(c);
                        continue;
                    }
                    if (st == 0)
                        continue;
                    re |= POLLIN; /* the first request may already be buffered */
                }
                if (re & POLLIN)
                    drop = conn_read(c) < 0;
                else if (re & (POLLERR | POLLHUP | POLLNVAL))
                    drop = 1;
                if (!drop && (out_pending(c) > 0 || c->closing))
                    drop = conn_flush(c) < 0;
                if (drop)
                    conn_free(c);
            }
            /* Opportunistically flush peers that were written to this round */
            for (int i = 0; i < MAX_CONNS; i++) {
                conn *c = g_conns[i];
                if (c && out_pending(c) > 0 && !c->closing && conn_flush(c) < 0)
                    conn_free(c);
            }
        }
        time_t now = time(NULL);
        if (now != last_hk) {
            housekeeping();
            last_hk = now;
        }
    }

    for (int i = 0; i < MAX_CONNS; i++)
        if (g_conns[i])
            conn_free(g_conns[i]);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i])
            session_destroy(g_sessions[i]);
    close(lfd);
    free(g_template);
    tls_cleanup();
    if (!cfg->quiet)
        fprintf(stderr, "\nbye\n");
    return 0;
}
