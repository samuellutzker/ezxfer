#include "server.h"
#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Serve a browser-based file transfer page. Open it on a computer, scan the\n"
            "QR code with a phone and send files in either direction.\n"
            "\n"
            "Options:\n"
            "  -p, --port PORT    TCP port to listen on (default 8080)\n"
            "  -b, --bind ADDR    IPv4 address to bind (default 0.0.0.0)\n"
            "  -u, --url URL      public base URL encoded in QR codes\n"
            "                     (default: http://<lan-ip>:<port>)\n"
            "  -w, --web FILE     serve FILE as the page template instead of the\n"
            "                     built-in one ({{VERSION}} is substituted)\n"
            "  -c, --cert FILE    serve HTTPS using this PEM certificate (chain);\n"
            "                     without it the server speaks plain HTTP\n"
            "  -k, --key FILE     PEM private key for --cert (default: read the\n"
            "                     key from the --cert file)\n"
            "  -t, --session-timeout SECONDS\n"
            "                     how long a session waits for its devices to\n"
            "                     reconnect after both dropped (default 120)\n"
            "      --no-qr        don't print a QR code in the terminal\n"
            "      --full-qr      print the terminal QR code at full height, for\n"
            "                     terminals that show gaps in the compact one\n"
            "                     (e.g. macOS Terminal)\n"
            "  -q, --quiet        no banner or logging\n"
            "  -h, --help         show this help\n"
            "\n"
            "TLS support: %s\n",
            prog, tls_available() ? "available" : "not compiled in (rebuild with OpenSSL)");
}

/* Matches -x / --long. Options that take a value only match when one follows. */
static int is_opt(const char *a, const char *s, const char *l) { return !strcmp(a, s) || !strcmp(a, l); }

/* Parses a whole decimal number in [min, max]; returns -1 (after a message) if invalid. */
static int int_arg(const char *what, const char *v, long min, long max, int *out)
{
    char *end;
    long n = strtol(v, &end, 10);
    if (!*v || *end || n < min || n > max) {
        fprintf(stderr, "invalid %s: %s\n", what, v);
        return -1;
    }
    *out = (int)n;
    return 0;
}

int main(int argc, char **argv)
{
    server_config cfg = {.bind_addr = "0.0.0.0", .port = 8080, .session_timeout = 120,
                         .print_qr = 1};

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        const char **str = NULL; /* string-valued option to fill */
        if (v && is_opt(a, "-p", "--port")) {
            if (int_arg("port", v, 1, 65535, &cfg.port) < 0)
                return 2;
            i++;
        } else if (v && is_opt(a, "-t", "--session-timeout")) {
            if (int_arg("session timeout", v, 0, 86400, &cfg.session_timeout) < 0)
                return 2;
            i++;
        } else if (v && is_opt(a, "-b", "--bind")) {
            str = &cfg.bind_addr;
        } else if (v && is_opt(a, "-u", "--url")) {
            str = &cfg.base_url;
        } else if (v && is_opt(a, "-w", "--web")) {
            str = &cfg.web_file;
        } else if (v && is_opt(a, "-c", "--cert")) {
            str = &cfg.tls_cert;
        } else if (v && is_opt(a, "-k", "--key")) {
            str = &cfg.tls_key;
        } else if (!strcmp(a, "--no-qr")) {
            cfg.print_qr = 0;
        } else if (!strcmp(a, "--full-qr")) {
            cfg.print_qr = 2;
        } else if (is_opt(a, "-q", "--quiet")) {
            cfg.quiet = 1;
        } else if (is_opt(a, "-h", "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown or incomplete option: %s\n\n", a);
            usage(argv[0]);
            return 2;
        }
        if (str) {
            *str = v;
            i++;
        }
    }
    if (cfg.tls_key && !cfg.tls_cert) {
        fprintf(stderr, "--key requires --cert\n");
        return 2;
    }
    return server_run(&cfg);
}
