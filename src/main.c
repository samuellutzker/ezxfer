#include "server.h"

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
            "      --no-qr        don't print a QR code in the terminal\n"
            "  -q, --quiet        no banner or logging\n"
            "  -h, --help         show this help\n",
            prog);
}

int main(int argc, char **argv)
{
    server_config cfg = {.bind_addr = "0.0.0.0", .port = 8080, .print_qr = 1};

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
    return server_run(&cfg);
}
