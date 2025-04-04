// gcc -o type_error2 type_error2.c
#include <stdio.h>
#include <unistd.h>

#define BUF_SIZE 0x20

void my_read(int fd, void *buf, unsigned int count) {
	read(fd, buf, count);
}

int main() {
	char buf[BUF_SIZE];
	int size;

	printf("input size:");
	scanf("%d", &size);

	if (size > BUF_SIZE-1) {
		printf("NOPE :(\n");
		return 1;
	}

	my_read(0, buf, size);
	printf("%s", buf);
	
	return 0;
}
