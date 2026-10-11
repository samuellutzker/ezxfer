#ifndef EZX_SERVER_H
#define EZX_SERVER_H

typedef struct {
    const char *bind_addr; /* e.g. "0.0.0.0" */
    int port;
    const char *base_url;  /* optional public URL override, e.g. "http://pc.lan:8080" */
    const char *web_file;  /* optional: serve this HTML template instead of the built-in */
    const char *tls_cert;  /* PEM certificate chain; enables HTTPS when set */
    const char *tls_key;   /* PEM private key (defaults to tls_cert) */
    int session_timeout;   /* seconds an empty session waits for its devices to return */
    int print_qr;          /* terminal QR code on startup: 0 off, 1 compact, 2 full height */
    int quiet;
} server_config;

/* Runs the event loop. Returns non-zero on startup failure. */
int server_run(const server_config *cfg);

/* Best-effort LAN IPv4 address of this machine (falls back to 127.0.0.1). */
void lan_address(char *out, unsigned outsz);

#endif
