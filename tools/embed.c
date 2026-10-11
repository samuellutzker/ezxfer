/* Build helper: turns a file into a C header with a byte array.
 * Usage: embed <input> <symbol> > out.h */
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <symbol>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 1;
    }
    printf("/* Generated from %s - do not edit. */\n", argv[1]);
    printf("#include <stddef.h>\n");
    printf("static const unsigned char %s[] = {", argv[2]);
    size_t n = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (n % 16 == 0)
            printf("\n ");
        printf(" 0x%02x,", c);
        n++;
    }
    printf("\n  0x00\n};\n");
    printf("static const size_t %s_len = %zu;\n", argv[2], n);
    fclose(f);
    return 0;
}
