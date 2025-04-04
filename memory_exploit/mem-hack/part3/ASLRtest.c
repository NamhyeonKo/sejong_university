// gcc -o ASLRtest ASLRtest.c -no-pie 
#include <stdio.h>
#include <stdlib.h>

char *glob = "KMOOC-MEMHACK";

int main(void) {
	char *heap_buf = malloc(0x10);
	char stack_buf[0x10];

	printf("data section: %p\n", glob);
	printf("heap section: %p\n", heap_buf);
	printf("stack section: %p\n", stack_buf);
	printf("library section: %p\n", printf);

	free(heap_buf);
	return 0;
}

