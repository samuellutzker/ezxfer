#include "proto.h"
#include "sha1.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- HTTP ---------------- */

static int ieq_prefix(const char *s, size_t n, const char *lit)
{
    size_t l = strlen(lit);
    if (n != l)
        return 0;
    for (size_t i = 0; i < l; i++)
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)lit[i]))
            return 0;
    return 1;
}

static int icontains(const char *s, size_t n, const char *lit)
{
    size_t l = strlen(lit);
    for (size_t i = 0; i + l <= n; i++) {
        size_t j = 0;
        while (j < l && tolower((unsigned char)s[i + j]) == tolower((unsigned char)lit[j]))
            j++;
        if (j == l)
            return 1;
    }
    return 0;
}

static void copy_trim(char *dst, size_t dsz, const char *s, size_t n)
{
    while (n && (*s == ' ' || *s == '\t')) {
        s++;
        n--;
    }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    if (n >= dsz)
        n = dsz - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

int http_parse_request(const char *buf, size_t len, http_request *req)
{
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i;
            break;
        }
    if (!end)
        return 0;

    memset(req, 0, sizeof *req);

    /* Request line: METHOD SP TARGET SP HTTP/x.y CRLF */
    const char *p = buf;
    const char *eol = memchr(p, '\r', (size_t)(end - p) + 1);
    const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
    if (!sp1 || sp1 == p || (size_t)(sp1 - p) >= sizeof req->method)
        return -1;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(eol - sp1 - 1));
    if (!sp2 || eol - sp2 < 9 || strncmp(sp2 + 1, "HTTP/1.", 7) != 0)
        return -1;
    memcpy(req->method, p, (size_t)(sp1 - p));

    const char *target = sp1 + 1;
    size_t tlen = (size_t)(sp2 - target);
    if (tlen == 0 || target[0] != '/')
        return -1;
    const char *q = memchr(target, '?', tlen);
    size_t plen = q ? (size_t)(q - target) : tlen;
    if (plen >= sizeof req->path)
        return -1;
    memcpy(req->path, target, plen);
    if (q) {
        size_t qlen = tlen - plen - 1;
        if (qlen >= sizeof req->query)
            return -1;
        memcpy(req->query, q + 1, qlen);
    }

    /* Headers */
    p = eol + 2;
    while (p < end) {
        eol = memchr(p, '\r', (size_t)(end - p) + 1);
        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon)
            return -1;
        size_t nlen = (size_t)(colon - p);
        const char *v = colon + 1;
        size_t vlen = (size_t)(eol - v);
        if (ieq_prefix(p, nlen, "Host"))
            copy_trim(req->host, sizeof req->host, v, vlen);
        else if (ieq_prefix(p, nlen, "Upgrade"))
            req->upgrade_ws = icontains(v, vlen, "websocket");
        else if (ieq_prefix(p, nlen, "Connection"))
            req->connection_up = icontains(v, vlen, "upgrade");
        else if (ieq_prefix(p, nlen, "Sec-WebSocket-Key"))
            copy_trim(req->ws_key, sizeof req->ws_key, v, vlen);
        else if (ieq_prefix(p, nlen, "Sec-WebSocket-Version")) {
            char tmp[16];
            copy_trim(tmp, sizeof tmp, v, vlen);
            req->ws_version = atoi(tmp);
        }
        p = eol + 2;
    }
    return (int)(end - buf) + 4;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int query_param(const char *query, const char *key, char *out, size_t outsz)
{
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        const char *seg_end = amp ? amp : p + strlen(p);
        if ((size_t)(seg_end - p) >= klen && strncmp(p, key, klen) == 0 &&
            (p[klen] == '=' || p + klen == seg_end)) {
            const char *v = p + klen + (p[klen] == '=' ? 1 : 0);
            size_t o = 0;
            while (v < seg_end) {
                int c = (unsigned char)*v;
                if (c == '+') {
                    c = ' ';
                    v++;
                } else if (c == '%' && seg_end - v >= 3 && hexval(v[1]) >= 0 &&
                           hexval(v[2]) >= 0) {
                    c = hexval(v[1]) * 16 + hexval(v[2]);
                    v += 3;
                } else {
                    v++;
                }
                if (o + 1 >= outsz)
                    return -1;
                out[o++] = (char)c;
            }
            out[o] = '\0';
            return (int)o;
        }
        p = amp ? amp + 1 : NULL;
    }
    return -1;
}

/* ---------------- WebSocket ---------------- */

void ws_accept_key(const char *client_key, char out[29])
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char buf[128];
    size_t kl = strlen(client_key);
    if (kl > sizeof buf - sizeof guid)
        kl = sizeof buf - sizeof guid;
    memcpy(buf, client_key, kl);
    memcpy(buf + kl, guid, sizeof guid - 1);
    uint8_t dig[20];
    sha1(buf, kl + sizeof guid - 1, dig);
    base64_encode(dig, 20, out);
}

long ws_parse_frame(uint8_t *buf, size_t len, size_t max_payload, int require_mask,
                    ws_frame *f)
{
    if (len < 2)
        return 0;
    f->fin = (buf[0] >> 7) & 1;
    f->opcode = buf[0] & 0x0F;
    f->masked = (buf[1] >> 7) & 1;
    if (buf[0] & 0x70)
        return WS_ERR_PROTOCOL; /* no extensions negotiated */
    switch (f->opcode) {
    case WS_OP_CONT: case WS_OP_TEXT: case WS_OP_BINARY:
        break;
    case WS_OP_CLOSE: case WS_OP_PING: case WS_OP_PONG:
        if (!f->fin || (buf[1] & 0x7F) > 125)
            return WS_ERR_PROTOCOL;
        break;
    default:
        return WS_ERR_PROTOCOL;
    }
    if (require_mask && !f->masked)
        return WS_ERR_PROTOCOL;

    size_t hl = 2;
    uint64_t pl = buf[1] & 0x7F;
    if (pl == 126) {
        if (len < 4)
            return 0;
        pl = (uint64_t)buf[2] << 8 | buf[3];
        hl = 4;
    } else if (pl == 127) {
        if (len < 10)
            return 0;
        pl = 0;
        for (int i = 0; i < 8; i++)
            pl = pl << 8 | buf[2 + i];
        if (pl >> 63)
            return WS_ERR_PROTOCOL;
        hl = 10;
    }
    if (pl > max_payload)
        return WS_ERR_TOO_BIG;
    uint8_t mask[4] = {0, 0, 0, 0};
    if (f->masked) {
        if (len < hl + 4)
            return 0;
        memcpy(mask, buf + hl, 4);
        hl += 4;
    }
    if (len < hl + pl)
        return 0;
    f->payload = buf + hl;
    f->len = pl;
    if (f->masked)
        for (uint64_t i = 0; i < pl; i++)
            f->payload[i] ^= mask[i & 3];
    return (long)(hl + pl);
}

size_t ws_frame_header(uint8_t *hdr, int opcode, uint64_t len)
{
    hdr[0] = (uint8_t)(0x80 | (opcode & 0x0F));
    if (len < 126) {
        hdr[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xFFFF) {
        hdr[1] = 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)len;
        return 4;
    }
    hdr[1] = 127;
    for (int i = 0; i < 8; i++)
        hdr[2 + i] = (uint8_t)(len >> (56 - 8 * i));
    return 10;
}
