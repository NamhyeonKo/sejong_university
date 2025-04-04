// gcc -o format1 format1.c -fno-stack-protector -no-pie -fno-pic
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
void vuln(char *string) {
  volatile int target;
  char buffer[64];
  target = 0;
  sprintf(buffer, string);
  
  if(target == 0xdeadbeef)
    printf("you have hit the target correctly :)\n");
  else
    printf("incorrect value :( %d\n", target);
}

int main(int argc, char **argv) {
  char input[64];
  fgets(input, sizeof(input), stdin);
  vuln(input);
}