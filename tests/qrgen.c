/* Test helper: encode stdin with the project's QR encoder and print the matrix.
 * Usage: qrgen <ecl 0-3> <mask -1..7> [svg] < data
 * Output: "<version> <ecl> <mask>" then one line of 0/1 per row (or the SVG). */
#include "qr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3)
        return 2;
    static uint8_t data[4096];
    size_t n = fread(data, 1, sizeof data, stdin);
    static qr_code q;
    if (qr_encode(data, n, atoi(argv[1]), 0, atoi(argv[2]), &q) != 0) {
        puts("TOO_LONG");
        return 1;
    }
    if (argc > 3 && strcmp(argv[3], "svg") == 0) {
        char *svg = qr_to_svg(&q, 4);
        fputs(svg, stdout);
        free(svg);
        return 0;
    }
    printf("%d %d %d\n", q.version, q.ecl, q.mask);
    for (int y = 0; y < q.size; y++) {
        for (int x = 0; x < q.size; x++)
            putchar('0' + q.mod[y][x]);
        putchar('\n');
    }
    return 0;
}
