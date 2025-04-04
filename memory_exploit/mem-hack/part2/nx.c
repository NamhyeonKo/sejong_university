// gcc -o nx-enabled nx.c
// gcc -o nx-disabled nx.c -z execstack

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
	char stack_buffer[256];
	char *heap_buffer = (char *) malloc(100 * sizeof(char));

	printf("pid: %d\n", getpid());
	gets(stack_buffer);

	free(heap_buffer);
	return 0;	

}
