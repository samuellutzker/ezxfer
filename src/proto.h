#ifndef EZX_PROTO_H
#define EZX_PROTO_H

#include <stddef.h>
#include <stdint.h>

/* ---------------- HTTP ---------------- */

typedef struct {
    char method[16];
    char path[512];   /* without query string */
    char query[1024]; /* without leading '?' */
    char host[256];
    char ws_key[64];
    int ws_version;
    int upgrade_ws;     /* "Upgrade: websocket" present */
    int connection_up;  /* "Connection" header contains "upgrade" */
} http_request;

/* Parse an HTTP/1.x request head from buf[0..len).
 * Returns the length of the head (including the final CRLFCRLF) on success,
 * 0 if more data is needed, -1 on malformed input. */
int http_parse_request(const char *buf, size_t len, http_request *req);

/* Look up `key` in an application/x-www-form-urlencoded query string and
 * percent-decode its value into out (NUL-terminated). Returns the decoded
 * length, or -1 if the key is absent or the value does not fit. */
int query_param(const char *query, const char *key, char *out, size_t outsz);

/* ---------------- WebSocket (RFC 6455) ---------------- */

enum {
    WS_OP_CONT = 0x0,
    WS_OP_TEXT = 0x1,
    WS_OP_BINARY = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING = 0x9,
    WS_OP_PONG = 0xA,
};

typedef struct {
    int fin;
    int opcode;
    int masked;
    uint8_t *payload; /* points into the parsed buffer (unmasked in place) */
    uint64_t len;
} ws_frame;

#define WS_ERR_PROTOCOL (-1)
#define WS_ERR_TOO_BIG (-2)

/* Compute Sec-WebSocket-Accept for a client key. out must hold 29 bytes. */
void ws_accept_key(const char *client_key, char out[29]);

/* Parse one frame from buf[0..len). On success unmasks the payload in place
 * and returns the total frame size consumed. Returns 0 if incomplete, or a
 * WS_ERR_* value. If require_mask is set, unmasked frames are rejected. */
long ws_parse_frame(uint8_t *buf, size_t len, size_t max_payload, int require_mask,
                    ws_frame *f);

/* Write an unmasked frame header for a final frame into hdr (>= 10 bytes).
 * Returns the header length. */
size_t ws_frame_header(uint8_t *hdr, int opcode, uint64_t len);

#endif
