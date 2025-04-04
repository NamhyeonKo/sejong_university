// gcc -o type_error1 type_error1.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	unsigned int size;
	char *buf;

	printf("input size: ");
	scanf("%u", &size);

	buf = (char *) malloc(size + 1);
	read(0, buf, size);

	printf("%s", buf);
	return 0;
}
