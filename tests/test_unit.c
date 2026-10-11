/* Unit tests for the protocol, crypto and QR modules. */
#include "proto.h"
#include "qr.h"
#include "sha1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (cond) {                                                                 \
            g_pass++;                                                               \
        } else {                                                                    \
            g_fail++;                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                           \
    } while (0)

static void hex(const uint8_t *d, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", d[i]);
}

static void test_sha1(void)
{
    struct { const char *in; const char *out; } v[] = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"The quick brown fox jumps over the lazy dog",
         "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t d[20];
        char h[41];
        sha1(v[i].in, strlen(v[i].in), d);
        hex(d, 20, h);
        CHECK(strcmp(h, v[i].out) == 0);
    }
    /* One million 'a' (FIPS 180 test vector) exercises multi-block input */
    char *big = malloc(1000000);
    memset(big, 'a', 1000000);
    uint8_t d[20];
    char h[41];
    sha1(big, 1000000, d);
    hex(d, 20, h);
    CHECK(strcmp(h, "34aa973cd4c4daa4f61eeb2bdbad27316534016f") == 0);
    free(big);
    /* Lengths around the padding boundary */
    const char *s70 = "0123456789012345678901234567890123456789"
                      "012345678901234567890123456789";
    struct { size_t n; const char *out; } b[] = {
        {55, "9f3a4ce7f66b1b74c34da2c5d732c39f81e0f8df"},
        {56, "0a40b8fbdaafb7c29651618ac15d27e772287130"},
        {63, "984b0f2f6d78c24020f5a79d409f67ab99302891"},
        {64, "cf0800f7644ace3cb4c3fa33388d3ba0ea3c8b6e"},
        {65, "92de3a8444fe6d15268f0ba810aa43bc8b3a4ffe"},
    };
    for (size_t i = 0; i < sizeof b / sizeof b[0]; i++) {
        sha1(s70, b[i].n, d);
        hex(d, 20, h);
        CHECK(strcmp(h, b[i].out) == 0);
    }
}

static void test_base64(void)
{
    struct { const char *in; const char *out; } v[] = {
        {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        char out[32];
        size_t n = base64_encode((const uint8_t *)v[i].in, strlen(v[i].in), out);
        CHECK(n == strlen(v[i].out));
        CHECK(strcmp(out, v[i].out) == 0);
    }
}

static void test_ws_accept(void)
{
    char out[29];
    ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", out); /* RFC 6455 section 1.3 */
    CHECK(strcmp(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
}

static void test_ws_frames(void)
{
    ws_frame f;
    /* RFC 6455 5.7: masked "Hello" */
    uint8_t masked[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
    CHECK(ws_parse_frame(masked, sizeof masked, 100, 1, &f) == (long)sizeof masked);
    CHECK(f.fin == 1 && f.opcode == WS_OP_TEXT && f.masked && f.len == 5);
    CHECK(memcmp(f.payload, "Hello", 5) == 0);

    /* Every truncated prefix is "incomplete" */
    uint8_t masked2[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
    for (size_t i = 0; i < sizeof masked2; i++)
        CHECK(ws_parse_frame(masked2, i, 100, 1, &f) == 0);

    /* Unmasked client frame rejected when masking is required */
    uint8_t unmasked[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
    CHECK(ws_parse_frame(unmasked, sizeof unmasked, 100, 1, &f) == WS_ERR_PROTOCOL);
    CHECK(ws_parse_frame(unmasked, sizeof unmasked, 100, 0, &f) == (long)sizeof unmasked);

    /* Fragmented: first fragment not final, continuation final */
    uint8_t frag1[] = {0x01, 0x83, 0, 0, 0, 0, 'H', 'e', 'l'};
    CHECK(ws_parse_frame(frag1, sizeof frag1, 100, 1, &f) == (long)sizeof frag1);
    CHECK(f.fin == 0 && f.opcode == WS_OP_TEXT);
    uint8_t frag2[] = {0x80, 0x82, 0, 0, 0, 0, 'l', 'o'};
    CHECK(ws_parse_frame(frag2, sizeof frag2, 100, 1, &f) == (long)sizeof frag2);
    CHECK(f.fin == 1 && f.opcode == WS_OP_CONT);

    /* Reserved bits, unknown opcode, fragmented/oversized control frames */
    uint8_t rsv[] = {0xC1, 0x80, 0, 0, 0, 0};
    CHECK(ws_parse_frame(rsv, sizeof rsv, 100, 1, &f) == WS_ERR_PROTOCOL);
    uint8_t badop[] = {0x83, 0x80, 0, 0, 0, 0};
    CHECK(ws_parse_frame(badop, sizeof badop, 100, 1, &f) == WS_ERR_PROTOCOL);
    uint8_t fragping[] = {0x09, 0x80, 0, 0, 0, 0};
    CHECK(ws_parse_frame(fragping, sizeof fragping, 100, 1, &f) == WS_ERR_PROTOCOL);
    uint8_t bigping[] = {0x89, 0xFE, 0x00, 0x80};
    CHECK(ws_parse_frame(bigping, sizeof bigping, 1000, 1, &f) == WS_ERR_PROTOCOL);

    /* 16-bit and 64-bit lengths, round-tripped through the header writer */
    size_t sizes[] = {0, 1, 125, 126, 127, 65535, 65536, 300000};
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        size_t n = sizes[k];
        uint8_t *buf = malloc(n + 14);
        size_t hl = ws_frame_header(buf, WS_OP_BINARY, n);
        CHECK(hl == (n < 126 ? 2u : n <= 65535 ? 4u : 10u));
        for (size_t i = 0; i < n; i++)
            buf[hl + i] = (uint8_t)(i * 7);
        CHECK(ws_parse_frame(buf, hl + n, 1 << 20, 0, &f) == (long)(hl + n));
        CHECK(f.len == n && f.opcode == WS_OP_BINARY && f.fin);
        int ok = 1;
        for (size_t i = 0; i < n; i++)
            ok &= f.payload[i] == (uint8_t)(i * 7);
        CHECK(ok);
        /* incomplete by one byte */
        if (n > 0)
            CHECK(ws_parse_frame(buf, hl + n - 1, 1 << 20, 0, &f) == 0);
        /* size limit */
        if (n > 1)
            CHECK(ws_parse_frame(buf, hl + n, n - 1, 0, &f) == WS_ERR_TOO_BIG);
        free(buf);
    }

    /* Masked 64-bit length frame */
    size_t n = 70000;
    uint8_t *buf = malloc(n + 14);
    buf[0] = 0x82;
    buf[1] = 0x80 | 127;
    for (int i = 0; i < 8; i++)
        buf[2 + i] = (uint8_t)((uint64_t)n >> (56 - 8 * i));
    uint8_t mask[4] = {1, 2, 3, 4};
    memcpy(buf + 10, mask, 4);
    for (size_t i = 0; i < n; i++)
        buf[14 + i] = (uint8_t)(i ^ mask[i & 3]);
    CHECK(ws_parse_frame(buf, n + 14, 1 << 20, 1, &f) == (long)(n + 14));
    int ok = 1;
    for (size_t i = 0; i < n; i++)
        ok &= f.payload[i] == (uint8_t)i;
    CHECK(ok);
    /* Unmasking at every length and alignment matches the byte-wise definition */
    int unmask_ok = 1;
    for (size_t len = 0; len < 100; len++)
        for (size_t align = 0; align < 8; align++) {
            uint8_t raw[8 + 14 + 100], expect[100];
            uint8_t key[4] = {(uint8_t)(len * 31 + 7), 0xA5, (uint8_t)align, 0x3C};
            uint8_t *fr = raw + align;
            size_t hl = 0;
            fr[hl++] = 0x82;
            fr[hl++] = (uint8_t)(0x80 | len);
            memcpy(fr + hl, key, 4);
            hl += 4;
            for (size_t i = 0; i < len; i++) {
                expect[i] = (uint8_t)(i * 13 + len);
                fr[hl + i] = expect[i] ^ key[i & 3];
            }
            if (ws_parse_frame(fr, hl + len, 1 << 20, 1, &f) != (long)(hl + len) ||
                memcmp(f.payload, expect, len) != 0)
                unmask_ok = 0;
        }
    CHECK(unmask_ok);

    /* MSB of a 64-bit length must be zero */
    buf[2] = 0x80;
    CHECK(ws_parse_frame(buf, n + 14, (size_t)-1, 1, &f) == WS_ERR_PROTOCOL);
    free(buf);
}

static void test_http(void)
{
    http_request r;
    const char *req = "GET /ws?s=ABC123&x=1 HTTP/1.1\r\n"
                      "Host: 192.168.1.5:8080\r\n"
                      "upgrade: WebSocket\r\n"
                      "Connection: keep-alive, Upgrade\r\n"
                      "Sec-WebSocket-Key:   dGhlIHNhbXBsZSBub25jZQ==  \r\n"
                      "Sec-WebSocket-Version: 13\r\n"
                      "\r\n"
                      "trailing";
    size_t len = strlen(req);
    int hl = http_parse_request(req, len, &r);
    CHECK(hl == (int)(strstr(req, "trailing") - req));
    CHECK(strcmp(r.method, "GET") == 0);
    CHECK(strcmp(r.path, "/ws") == 0);
    CHECK(strcmp(r.query, "s=ABC123&x=1") == 0);
    CHECK(strcmp(r.host, "192.168.1.5:8080") == 0);
    CHECK(r.upgrade_ws == 1 && r.connection_up == 1 && r.ws_version == 13);
    CHECK(strcmp(r.ws_key, "dGhlIHNhbXBsZSBub25jZQ==") == 0);

    /* incomplete heads */
    for (size_t i = 0; i < (size_t)hl; i++)
        CHECK(http_parse_request(req, i, &r) == 0);

    const char *plain = "GET / HTTP/1.0\r\n\r\n";
    CHECK(http_parse_request(plain, strlen(plain), &r) == (int)strlen(plain));
    CHECK(strcmp(r.path, "/") == 0 && r.query[0] == 0 && !r.upgrade_ws);

    const char *bad[] = {
        "GARBAGE\r\n\r\n",
        "GET /\r\n\r\n",
        "GET / FTP/1.0\r\n\r\n",
        "GET noslash HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nNoColonHeader\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(http_parse_request(bad[i], strlen(bad[i]), &r) == -1);

    /* overly long path */
    char longreq[2048];
    snprintf(longreq, sizeof longreq, "GET /%0900d HTTP/1.1\r\n\r\n", 0);
    CHECK(http_parse_request(longreq, strlen(longreq), &r) == -1);
}

static void test_query(void)
{
    char out[64];
    CHECK(query_param("s=ABC&d=http%3A%2F%2Fx%2F%3Fs%3D1", "d", out, sizeof out) == 13);
    CHECK(strcmp(out, "http://x/?s=1") == 0);
    CHECK(query_param("s=ABC&d=x", "s", out, sizeof out) == 3 && strcmp(out, "ABC") == 0);
    CHECK(query_param("ss=1&s=2", "s", out, sizeof out) == 1 && strcmp(out, "2") == 0);
    CHECK(query_param("a=hello+world%21", "a", out, sizeof out) > 0 &&
          strcmp(out, "hello world!") == 0);
    CHECK(query_param("a=%zz%4", "a", out, sizeof out) > 0 && strcmp(out, "%zz%4") == 0);
    CHECK(query_param("flag&b=2", "flag", out, sizeof out) == 0 && out[0] == 0);
    CHECK(query_param("a=1", "b", out, sizeof out) == -1);
    CHECK(query_param("", "a", out, sizeof out) == -1);
    CHECK(query_param("a=0123456789", "a", out, 5) == -1); /* does not fit */
}

static int finder_ok(const qr_code *q, int x0, int y0)
{
    for (int dy = 0; dy < 7; dy++)
        for (int dx = 0; dx < 7; dx++) {
            int ring = dx == 0 || dy == 0 || dx == 6 || dy == 6;
            int core = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
            if (qr_module(q, x0 + dx, y0 + dy) != (ring || core))
                return 0;
        }
    return 1;
}

static void test_qr(void)
{
    static qr_code q;
    /* Byte-mode capacities: (version, ecl) -> max bytes */
    struct { int ver, ecl, cap; } caps[] = {
        {1, QR_ECC_L, 17}, {1, QR_ECC_M, 14}, {1, QR_ECC_Q, 11}, {1, QR_ECC_H, 7},
        {2, QR_ECC_M, 26}, {5, QR_ECC_Q, 60}, {10, QR_ECC_M, 213}, {10, QR_ECC_L, 271},
        {25, QR_ECC_H, 535}, {40, QR_ECC_L, 2953}, {40, QR_ECC_H, 1273},
    };
    static uint8_t data[3000];
    for (size_t i = 0; i < sizeof data; i++)
        data[i] = (uint8_t)('a' + i % 26);
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; i++) {
        CHECK(qr_encode(data, (size_t)caps[i].cap, caps[i].ecl, 0, -1, &q) == 0);
        CHECK(q.version == caps[i].ver);
        if (caps[i].ver < 40) {
            CHECK(qr_encode(data, (size_t)caps[i].cap + 1, caps[i].ecl, 0, -1, &q) == 0);
            CHECK(q.version == caps[i].ver + 1);
        } else {
            CHECK(qr_encode(data, (size_t)caps[i].cap + 1, caps[i].ecl, 0, -1, &q) == -1);
        }
    }

    /* Structure: size, finder patterns, timing, dark module */
    const char *url = "http://192.168.1.23:8080/?s=K7PQ2M";
    CHECK(qr_encode((const uint8_t *)url, strlen(url), QR_ECC_M, 1, -1, &q) == 0);
    CHECK(q.size == 17 + 4 * q.version);
    CHECK(q.ecl >= QR_ECC_M);
    CHECK(q.mask >= 0 && q.mask <= 7);
    CHECK(finder_ok(&q, 0, 0));
    CHECK(finder_ok(&q, q.size - 7, 0));
    CHECK(finder_ok(&q, 0, q.size - 7));
    int timing = 1;
    for (int i = 8; i < q.size - 8; i++)
        timing &= qr_module(&q, i, 6) == (i % 2 == 0) && qr_module(&q, 6, i) == (i % 2 == 0);
    CHECK(timing);
    CHECK(qr_module(&q, 8, q.size - 8) == 1);

    /* Forced masks are honoured and change the symbol */
    static qr_code a, b;
    CHECK(qr_encode((const uint8_t *)url, strlen(url), QR_ECC_M, 0, 2, &a) == 0 && a.mask == 2);
    CHECK(qr_encode((const uint8_t *)url, strlen(url), QR_ECC_M, 0, 5, &b) == 0 && b.mask == 5);
    CHECK(memcmp(a.mod, b.mod, sizeof a.mod) != 0);

    /* Boost raises ECC level when it fits in the same version */
    CHECK(qr_encode((const uint8_t *)"hi", 2, QR_ECC_L, 1, -1, &q) == 0);
    CHECK(q.version == 1 && q.ecl == QR_ECC_H);
    CHECK(qr_encode((const uint8_t *)"hi", 2, QR_ECC_L, 0, -1, &q) == 0 && q.ecl == QR_ECC_L);
    CHECK(qr_encode((const uint8_t *)"", 0, QR_ECC_M, 0, -1, &q) == 0 && q.version == 1);

    /* Version information is present from version 7 on */
    CHECK(qr_encode(data, 200, QR_ECC_L, 0, -1, &q) == 0 && q.version >= 7);
    CHECK(finder_ok(&q, q.size - 7, 0));
    CHECK(qr_encode(data, 10, 9, 0, -1, &q) == -1); /* bad ecl */

    /* SVG rendering */
    CHECK(qr_encode((const uint8_t *)url, strlen(url), QR_ECC_M, 1, -1, &q) == 0);
    char *svg = qr_to_svg(&q, 4);
    CHECK(svg != NULL);
    char vb[64];
    snprintf(vb, sizeof vb, "viewBox=\"0 0 %d %d\"", q.size + 8, q.size + 8);
    CHECK(strstr(svg, vb) != NULL);
    CHECK(strstr(svg, "M4,4h7v1h-7z") != NULL); /* top row of the top-left finder */
    CHECK(strstr(svg, "</svg>") != NULL);
    free(svg);

    /* The largest symbol renders without overflowing its buffer */
    CHECK(qr_encode(data, 2953, QR_ECC_L, 0, -1, &q) == 0 && q.size == 177);
    svg = qr_to_svg(&q, 4);
    CHECK(svg && strstr(svg, "</svg>"));
    free(svg);
}

int main(void)
{
    test_sha1();
    test_base64();
    test_ws_accept();
    test_ws_frames();
    test_http();
    test_query();
    test_qr();
    printf("unit tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
