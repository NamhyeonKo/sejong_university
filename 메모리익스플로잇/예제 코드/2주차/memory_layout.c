// gcc -o memory_layout memory_layout.c

#include <stdio.h>
#include <stdlib.h>

int global_variable = 100;
char global_array[1024];

void func(int arg){
    printf("stack segment near: %p\n",&arg);
}

int main(int argc, char  **argv){
    char *ptr;
    ptr = malloc(sizeof(char));

    func(100);

    printf("heap segment near: %p\n",ptr);
    printf("BSS segment near: %p\n", global_array);
    printf("initialized data segment near: %p\n", &global_variable);

    return(0);
}