// gcc -o path_traversal path_traversal.c
#include <stdio.h>
#include <string.h>

void read_file(char *filename) {
    char filepath[256] = "/var/www/html/";
    strcat(filepath, filename);
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        printf("cannot open file\n");
        return;
    }
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: %s <filename>\n", argv[0]);
        return 1;
    }
    read_file(argv[1]);
    return 0;
}
