// gcc -o where where.c -no-pie -fno-pic
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	char *heap_buffer = malloc(0x30);
	printf("where??\n");
	free(heap_buffer);
	return 0;
}
