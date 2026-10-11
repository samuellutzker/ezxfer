#ifndef EZX_TLS_H
#define EZX_TLS_H

#include <stddef.h>

/* Thin wrapper around OpenSSL so the server stays readable and the program
 * still builds without it (compile with -DEZX_TLS to enable). */

typedef struct tls_conn tls_conn;

enum { TLS_WANT_READ = 1, TLS_WANT_WRITE = 2 };

/* Non-zero if this binary was built with TLS support. */
int tls_available(void);

/* Load a PEM certificate chain and private key (key_file may be NULL when the
 * key is in cert_file). Returns 0 on success, or -1 with a message in err. */
int tls_init(const char *cert_file, const char *key_file, char *err, size_t errsz);

tls_conn *tls_new(int fd);

/* 1 = handshake complete, 0 = in progress (*want says what to wait for),
 * -1 = failed. */
int tls_handshake(tls_conn *t, int *want);

/* > 0 bytes transferred, 0 = would block, -1 = closed or failed. */
long tls_read(tls_conn *t, void *buf, size_t n);
long tls_write(tls_conn *t, const void *buf, size_t n);

/* Decrypted bytes already buffered inside the TLS layer (poll() can't see them). */
int tls_pending(tls_conn *t);

/* Sends close_notify (best effort) and frees the connection. */
void tls_free(tls_conn *t);

void tls_cleanup(void);

#endif
