#include "qr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Error-correction codewords per block, indexed [ecl][version]. */
static const int8_t ECC_CW_PER_BLOCK[4][41] = {
    {-1, 7,  10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
     28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
     26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
    {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
     28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
     30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
};

/* Number of error-correction blocks, indexed [ecl][version]. */
static const int8_t NUM_ECC_BLOCKS[4][41] = {
    {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
     8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
    {-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
     17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
    {-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
     23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
    {-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
     25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
};

/* Format-information bits for each ECC level (L, M, Q, H). */
static const int ECL_FORMAT_BITS[4] = {1, 0, 3, 2};

#define MAX_RAW_CODEWORDS 3706

static int num_raw_modules(int ver)
{
    int r = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int na = ver / 7 + 2;
        r -= (25 * na - 10) * na - 55;
        if (ver >= 7)
            r -= 36;
    }
    return r;
}

static int num_data_codewords(int ver, int ecl)
{
    return num_raw_modules(ver) / 8 - ECC_CW_PER_BLOCK[ecl][ver] * NUM_ECC_BLOCKS[ecl][ver];
}

/* ---- Reed-Solomon over GF(2^8) with polynomial 0x11D ---- */

static uint8_t gf_mul(uint8_t x, uint8_t y)
{
    int z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * x;
    }
    return (uint8_t)z;
}

static void rs_divisor(int degree, uint8_t *res)
{
    memset(res, 0, (size_t)degree);
    res[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            res[j] = gf_mul(res[j], root);
            if (j + 1 < degree)
                res[j] ^= res[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
}

static void rs_remainder(const uint8_t *data, int len, const uint8_t *div, int degree,
                         uint8_t *res)
{
    memset(res, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        uint8_t f = data[i] ^ res[0];
        memmove(res, res + 1, (size_t)degree - 1);
        res[degree - 1] = 0;
        for (int j = 0; j < degree; j++)
            res[j] ^= gf_mul(div[j], f);
    }
}

/* ---- Function patterns ---- */

static void set_fn(qr_code *q, int x, int y, int dark)
{
    q->mod[y][x] = (uint8_t)(dark != 0);
    q->fn[y][x] = 1;
}

static int iabs(int v) { return v < 0 ? -v : v; }
static int imax(int a, int b) { return a > b ? a : b; }

static void draw_finder(qr_code *q, int cx, int cy)
{
    for (int dy = -4; dy <= 4; dy++)
        for (int dx = -4; dx <= 4; dx++) {
            int x = cx + dx, y = cy + dy;
            if (x < 0 || y < 0 || x >= q->size || y >= q->size)
                continue;
            int d = imax(iabs(dx), iabs(dy));
            set_fn(q, x, y, d != 2 && d != 4);
        }
}

static void draw_alignment(qr_code *q, int cx, int cy)
{
    for (int dy = -2; dy <= 2; dy++)
        for (int dx = -2; dx <= 2; dx++)
            set_fn(q, cx + dx, cy + dy, imax(iabs(dx), iabs(dy)) != 1);
}

static int alignment_positions(int ver, int size, int pos[7])
{
    if (ver == 1)
        return 0;
    int n = ver / 7 + 2;
    int step = ver == 32 ? 26 : (ver * 4 + n * 2 + 1) / (n * 2 - 2) * 2;
    pos[0] = 6;
    for (int i = n - 1, p = size - 7; i >= 1; i--, p -= step)
        pos[i] = p;
    return n;
}

static void draw_format(qr_code *q, int mask)
{
    int data = ECL_FORMAT_BITS[q->ecl] << 3 | mask;
    int rem = data;
    for (int i = 0; i < 10; i++)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = (data << 10 | rem) ^ 0x5412;
    int n = q->size;

    for (int i = 0; i <= 5; i++)
        set_fn(q, 8, i, (bits >> i) & 1);
    set_fn(q, 8, 7, (bits >> 6) & 1);
    set_fn(q, 8, 8, (bits >> 7) & 1);
    set_fn(q, 7, 8, (bits >> 8) & 1);
    for (int i = 9; i < 15; i++)
        set_fn(q, 14 - i, 8, (bits >> i) & 1);

    for (int i = 0; i < 8; i++)
        set_fn(q, n - 1 - i, 8, (bits >> i) & 1);
    for (int i = 8; i < 15; i++)
        set_fn(q, 8, n - 15 + i, (bits >> i) & 1);
    set_fn(q, 8, n - 8, 1);
}

static void draw_version(qr_code *q)
{
    if (q->version < 7)
        return;
    int rem = q->version;
    for (int i = 0; i < 12; i++)
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    long bits = (long)q->version << 12 | rem;
    for (int i = 0; i < 18; i++) {
        int bit = (int)((bits >> i) & 1);
        int a = q->size - 11 + i % 3, b = i / 3;
        set_fn(q, a, b, bit);
        set_fn(q, b, a, bit);
    }
}

static void draw_function_patterns(qr_code *q)
{
    int n = q->size;
    for (int i = 0; i < n; i++) {
        set_fn(q, 6, i, i % 2 == 0);
        set_fn(q, i, 6, i % 2 == 0);
    }
    draw_finder(q, 3, 3);
    draw_finder(q, n - 4, 3);
    draw_finder(q, 3, n - 4);

    int pos[7];
    int na = alignment_positions(q->version, n, pos);
    for (int i = 0; i < na; i++)
        for (int j = 0; j < na; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == na - 1) || (i == na - 1 && j == 0))
                continue;
            draw_alignment(q, pos[i], pos[j]);
        }
    draw_format(q, 0); /* reserve area; real bits drawn after masking */
    draw_version(q);
}

static void draw_codewords(qr_code *q, const uint8_t *data, int len)
{
    int n = q->size, i = 0;
    for (int right = n - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        for (int vert = 0; vert < n; vert++)
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                int upward = ((right + 1) & 2) == 0;
                int y = upward ? n - 1 - vert : vert;
                if (!q->fn[y][x] && i < len * 8) {
                    q->mod[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1;
                    i++;
                }
            }
    }
}

static int mask_bit(int mask, int x, int y)
{
    switch (mask) {
    case 0: return (x + y) % 2 == 0;
    case 1: return y % 2 == 0;
    case 2: return x % 3 == 0;
    case 3: return (x + y) % 3 == 0;
    case 4: return (x / 3 + y / 2) % 2 == 0;
    case 5: return x * y % 2 + x * y % 3 == 0;
    case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
    }
}

static void apply_mask(qr_code *q, int mask)
{
    for (int y = 0; y < q->size; y++)
        for (int x = 0; x < q->size; x++)
            if (!q->fn[y][x] && mask_bit(mask, x, y))
                q->mod[y][x] ^= 1;
}

/* Module accessor treating out-of-bounds as light; `t` transposes. */
static int at(const qr_code *q, int a, int b, int t)
{
    return t ? qr_module(q, b, a) : qr_module(q, a, b);
}

static long penalty(const qr_code *q)
{
    int n = q->size;
    long p = 0;

    for (int t = 0; t < 2; t++) {
        for (int b = 0; b < n; b++) {
            /* N1: runs of five or more same-coloured modules */
            int run = 1;
            for (int a = 1; a < n; a++) {
                if (at(q, a, b, t) == at(q, a - 1, b, t)) {
                    run++;
                } else {
                    if (run >= 5)
                        p += run - 2;
                    run = 1;
                }
            }
            if (run >= 5)
                p += run - 2;

            /* N3: 1:1:3:1:1 finder-like pattern with 4 light modules on a side */
            static const int pat[7] = {1, 0, 1, 1, 1, 0, 1};
            for (int a = 0; a + 7 <= n; a++) {
                int k = 0;
                while (k < 7 && at(q, a + k, b, t) == pat[k])
                    k++;
                if (k < 7)
                    continue;
                int before = 1, after = 1;
                for (int d = 1; d <= 4; d++) {
                    before &= !at(q, a - d, b, t);
                    after &= !at(q, a + 6 + d, b, t);
                }
                if (before || after)
                    p += 40;
            }
        }
    }

    /* N2: 2x2 blocks */
    for (int y = 0; y + 1 < n; y++)
        for (int x = 0; x + 1 < n; x++) {
            int c = q->mod[y][x];
            if (c == q->mod[y][x + 1] && c == q->mod[y + 1][x] && c == q->mod[y + 1][x + 1])
                p += 3;
        }

    /* N4: dark/light balance */
    long dark = 0, total = (long)n * n;
    for (int y = 0; y < n; y++)
        for (int x = 0; x < n; x++)
            dark += q->mod[y][x];
    long dev = dark * 20 - total * 10;
    if (dev < 0)
        dev = -dev;
    long k = (dev + total - 1) / total - 1;
    p += k * 10;
    return p;
}

typedef struct {
    uint8_t *buf;
    int bits;
} bitbuf;

static void put_bits(bitbuf *bb, unsigned val, int n)
{
    for (int i = n - 1; i >= 0; i--, bb->bits++)
        if ((val >> i) & 1)
            bb->buf[bb->bits >> 3] |= (uint8_t)(0x80 >> (bb->bits & 7));
}

int qr_encode(const uint8_t *data, size_t len, int ecl, int boost, int force_mask,
              qr_code *q)
{
    if (ecl < 0 || ecl > 3)
        return -1;

    int ver, need = 0;
    for (ver = 1; ver <= 40; ver++) {
        int cc = ver <= 9 ? 8 : 16;
        if (len >= (size_t)1 << cc)
            continue;
        need = 4 + cc + 8 * (int)len;
        if (need <= num_data_codewords(ver, ecl) * 8)
            break;
    }
    if (ver > 40)
        return -1;
    if (boost)
        for (int e = ecl + 1; e <= QR_ECC_H; e++)
            if (need <= num_data_codewords(ver, e) * 8)
                ecl = e;

    memset(q, 0, sizeof *q);
    q->version = ver;
    q->size = 17 + 4 * ver;
    q->ecl = ecl;

    /* Data codewords */
    uint8_t cw[MAX_RAW_CODEWORDS];
    memset(cw, 0, sizeof cw);
    bitbuf bb = {cw, 0};
    int cap = num_data_codewords(ver, ecl) * 8;
    put_bits(&bb, 0x4, 4);
    put_bits(&bb, (unsigned)len, ver <= 9 ? 8 : 16);
    for (size_t i = 0; i < len; i++)
        put_bits(&bb, data[i], 8);
    int term = cap - bb.bits < 4 ? cap - bb.bits : 4;
    put_bits(&bb, 0, term);
    put_bits(&bb, 0, (8 - bb.bits % 8) % 8);
    for (uint8_t pad = 0xEC; bb.bits < cap; pad ^= 0xEC ^ 0x11)
        put_bits(&bb, pad, 8);

    /* Split into blocks, add ECC, interleave */
    int nb = NUM_ECC_BLOCKS[ecl][ver];
    int eccl = ECC_CW_PER_BLOCK[ecl][ver];
    int raw = num_raw_modules(ver) / 8;
    int nshort = nb - raw % nb;
    int shortlen = raw / nb;
    uint8_t div[30], ecc[81][30];
    int dlen[81], doff[81];
    rs_divisor(eccl, div);
    for (int i = 0, k = 0; i < nb; i++) {
        dlen[i] = shortlen - eccl + (i < nshort ? 0 : 1);
        doff[i] = k;
        rs_remainder(cw + k, dlen[i], div, eccl, ecc[i]);
        k += dlen[i];
    }
    uint8_t out[MAX_RAW_CODEWORDS];
    int o = 0;
    for (int i = 0; i <= shortlen - eccl; i++)
        for (int j = 0; j < nb; j++)
            if (i < dlen[j])
                out[o++] = cw[doff[j] + i];
    for (int i = 0; i < eccl; i++)
        for (int j = 0; j < nb; j++)
            out[o++] = ecc[j][i];

    draw_function_patterns(q);
    draw_codewords(q, out, o);

    int mask = force_mask;
    if (mask < 0 || mask > 7) {
        long best = -1;
        for (int m = 0; m < 8; m++) {
            apply_mask(q, m);
            draw_format(q, m);
            long pen = penalty(q);
            if (best < 0 || pen < best) {
                best = pen;
                mask = m;
            }
            apply_mask(q, m);
        }
    }
    apply_mask(q, mask);
    draw_format(q, mask);
    q->mask = mask;
    return 0;
}
