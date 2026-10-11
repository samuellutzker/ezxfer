#ifndef EZX_QR_H
#define EZX_QR_H

#include <stddef.h>
#include <stdint.h>

/* Minimal QR Code Model 2 encoder (ISO/IEC 18004), byte mode only.
 * Supports versions 1-40 and all four error-correction levels. */

#define QR_MAX_SIZE 177

enum { QR_ECC_L = 0, QR_ECC_M = 1, QR_ECC_Q = 2, QR_ECC_H = 3 };

typedef struct {
    int version; /* 1..40 */
    int size;    /* 17 + 4 * version */
    int ecl;     /* QR_ECC_* actually used (may be boosted) */
    int mask;    /* 0..7 */
    uint8_t mod[QR_MAX_SIZE][QR_MAX_SIZE]; /* [y][x], 1 = dark */
    uint8_t fn[QR_MAX_SIZE][QR_MAX_SIZE];  /* internal: function module map */
} qr_code;

/* Encode `len` bytes. `ecl` is the minimum error-correction level; when
 * `boost` is non-zero a higher level is used if it fits in the same version.
 * `force_mask` selects a mask (0..7) or -1 for automatic selection.
 * Returns 0 on success, -1 if the data does not fit in version 40. */
int qr_encode(const uint8_t *data, size_t len, int ecl, int boost,
              int force_mask, qr_code *qr);

static inline int qr_module(const qr_code *qr, int x, int y)
{
    return x >= 0 && y >= 0 && x < qr->size && y < qr->size && qr->mod[y][x];
}

/* Render as a standalone SVG document with `border` quiet-zone modules.
 * Returns a malloc'd NUL-terminated string (caller frees) or NULL. */
char *qr_to_svg(const qr_code *qr, int border);

#endif
