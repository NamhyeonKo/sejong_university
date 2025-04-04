// gcc -o systemfunc systemfunc.c
#include <unistd.h>

int main(void) {
	system("ls");
	return 0;
}
