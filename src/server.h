#ifndef EZX_SERVER_H
#define EZX_SERVER_H

typedef struct {
    const char *bind_addr; /* e.g. "0.0.0.0" */
    int port;
    const char *base_url;  /* optional public URL override, e.g. "http://pc.lan:8080" */
    const char *web_file;  /* optional: serve this HTML template instead of the built-in */
    int print_qr;          /* print a terminal QR code on startup */
    int quiet;
} server_config;

/* Runs the event loop. Returns non-zero on startup failure. */
int server_run(const server_config *cfg);

/* Best-effort LAN IPv4 address of this machine (falls back to 127.0.0.1). */
void lan_address(char *out, unsigned outsz);

#endif
