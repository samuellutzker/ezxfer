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
            "  -q, --quiet        no banner or logging\n"
            "  -h, --help         show this help\n"
            "\n"
            "TLS support: %s\n",
            prog, tls_available() ? "available" : "not compiled in (rebuild with OpenSSL)");
}

int main(int argc, char **argv)
{
    server_config cfg = {.bind_addr = "0.0.0.0", .port = 8080, .session_timeout = 120,
                         .print_qr = 1};

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *next = i + 1 < argc ? argv[i + 1] : NULL;
        if ((!strcmp(a, "-p") || !strcmp(a, "--port")) && next) {
            char *end;
            long p = strtol(next, &end, 10);
            if (*end || p < 1 || p > 65535) {
                fprintf(stderr, "invalid port: %s\n", next);
                return 2;
            }
            cfg.port = (int)p;
            i++;
        } else if ((!strcmp(a, "-b") || !strcmp(a, "--bind")) && next) {
            cfg.bind_addr = next;
            i++;
        } else if ((!strcmp(a, "-u") || !strcmp(a, "--url")) && next) {
            cfg.base_url = next;
            i++;
        } else if ((!strcmp(a, "-w") || !strcmp(a, "--web")) && next) {
            cfg.web_file = next;
            i++;
        } else if ((!strcmp(a, "-c") || !strcmp(a, "--cert")) && next) {
            cfg.tls_cert = next;
            i++;
        } else if ((!strcmp(a, "-k") || !strcmp(a, "--key")) && next) {
            cfg.tls_key = next;
            i++;
        } else if ((!strcmp(a, "-t") || !strcmp(a, "--session-timeout")) && next) {
            char *end;
            long t = strtol(next, &end, 10);
            if (*end || t < 0 || t > 86400) {
                fprintf(stderr, "invalid session timeout: %s\n", next);
                return 2;
            }
            cfg.session_timeout = (int)t;
            i++;
        } else if (!strcmp(a, "--no-qr")) {
            cfg.print_qr = 0;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            cfg.quiet = 1;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown or incomplete option: %s\n\n", a);
            usage(argv[0]);
            return 2;
        }
    }
    if (cfg.tls_key && !cfg.tls_cert) {
        fprintf(stderr, "--key requires --cert\n");
        return 2;
    }
    return server_run(&cfg);
}
