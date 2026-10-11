#include "tls.h"

#include <stdio.h>

#ifdef EZX_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

struct tls_conn {
    SSL *ssl;
    size_t retry_len; /* length of a write that must be retried unchanged */
};

static SSL_CTX *g_ctx;

int tls_available(void) { return 1; }

static void last_error(const char *what, const char *file, char *err, size_t errsz)
{
    unsigned long e = ERR_peek_last_error();
    char reason[256] = "unknown error";
    if (e)
        ERR_error_string_n(e, reason, sizeof reason);
    snprintf(err, errsz, "%s %s: %s", what, file, reason);
    ERR_clear_error();
}

int tls_init(const char *cert_file, const char *key_file, char *err, size_t errsz)
{
    if (!key_file)
        key_file = cert_file;
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) {
        snprintf(err, errsz, "cannot create TLS context");
        return -1;
    }
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(g_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(g_ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_use_certificate_chain_file(g_ctx, cert_file) != 1) {
        last_error("cannot load certificate", cert_file, err, errsz);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == X509_R_KEY_VALUES_MISMATCH)
            last_error("private key does not match certificate", cert_file, err, errsz);
        else
            last_error("cannot load private key", key_file, err, errsz);
        return -1;
    }
    if (SSL_CTX_check_private_key(g_ctx) != 1) {
        last_error("private key does not match certificate", cert_file, err, errsz);
        return -1;
    }
    return 0;
}

tls_conn *tls_new(int fd)
{
    tls_conn *t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->ssl = SSL_new(g_ctx);
    if (!t->ssl || SSL_set_fd(t->ssl, fd) != 1) {
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    SSL_set_accept_state(t->ssl);
    return t;
}

/* Maps an SSL error to 0 (retry later) or -1 (fatal). */
static int classify(tls_conn *t, int ret, int *want)
{
    switch (SSL_get_error(t->ssl, ret)) {
    case SSL_ERROR_WANT_READ:
        if (want)
            *want = TLS_WANT_READ;
        return 0;
    case SSL_ERROR_WANT_WRITE:
        if (want)
            *want = TLS_WANT_WRITE;
        return 0;
    default:
        ERR_clear_error();
        return -1;
    }
}

int tls_handshake(tls_conn *t, int *want)
{
    ERR_clear_error();
    int r = SSL_do_handshake(t->ssl);
    if (r == 1)
        return 1;
    return classify(t, r, want);
}

long tls_read(tls_conn *t, void *buf, size_t n)
{
    ERR_clear_error();
    int r = SSL_read(t->ssl, buf, n > 0x7fffffff ? 0x7fffffff : (int)n);
    if (r > 0)
        return r;
    return classify(t, r, NULL);
}

long tls_write(tls_conn *t, const void *buf, size_t n)
{
    /* A write that returned WANT_* must be retried with the same length. */
    if (t->retry_len && t->retry_len <= n)
        n = t->retry_len;
    else if (n > 65536)
        n = 65536;
    ERR_clear_error();
    int r = SSL_write(t->ssl, buf, (int)n);
    if (r > 0) {
        t->retry_len = 0;
        return r;
    }
    int c = classify(t, r, NULL);
    if (c == 0)
        t->retry_len = n;
    return c;
}

int tls_pending(tls_conn *t) { return t ? SSL_pending(t->ssl) : 0; }

void tls_free(tls_conn *t)
{
    if (!t)
        return;
    if (SSL_is_init_finished(t->ssl)) {
        ERR_clear_error();
        SSL_shutdown(t->ssl); /* non-blocking: send close_notify if possible */
    }
    SSL_free(t->ssl);
    ERR_clear_error();
    free(t);
}

void tls_cleanup(void)
{
    SSL_CTX_free(g_ctx);
    g_ctx = NULL;
}

#else /* !EZX_TLS */

struct tls_conn {
    int unused;
};

int tls_available(void) { return 0; }

int tls_init(const char *cert_file, const char *key_file, char *err, size_t errsz)
{
    (void)cert_file;
    (void)key_file;
    snprintf(err, errsz, "this build has no TLS support (rebuild with OpenSSL: make TLS=1)");
    return -1;
}

tls_conn *tls_new(int fd) { (void)fd; return NULL; }
int tls_handshake(tls_conn *t, int *want) { (void)t; (void)want; return -1; }
long tls_read(tls_conn *t, void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }
long tls_write(tls_conn *t, const void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }
int tls_pending(tls_conn *t) { (void)t; return 0; }
void tls_free(tls_conn *t) { (void)t; }
void tls_cleanup(void) {}

#endif
