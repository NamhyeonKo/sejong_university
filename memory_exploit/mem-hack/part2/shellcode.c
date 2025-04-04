// gcc -o shellcode shellcode.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic
#include <unistd.h>

int main() {
	execve("/bin/sh", NULL, NULL);
}
