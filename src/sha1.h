#ifndef EZX_SHA1_H
#define EZX_SHA1_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-1 (FIPS 180-1). Used only for the WebSocket handshake. */
void sha1(const void *data, size_t len, uint8_t digest[20]);

/* Standard Base64 (RFC 4648) with padding. `out` must hold 4*((len+2)/3)+1
 * bytes. Returns the number of characters written (excluding the NUL). */
size_t base64_encode(const uint8_t *in, size_t len, char *out);

#endif
