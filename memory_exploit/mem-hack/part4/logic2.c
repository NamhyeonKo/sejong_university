// gcc -o logic2 logic2.c
#include <stdio.h>

char *p = NULL;

void sensitive() {
	char sensitive_data[] = "sensitive!";
	p = sensitive_data;
}

void print_pointer() {
	printf("p: %s\n", p);
}

int main() {
	sensitive();
	print_pointer();

	return 0;
}
