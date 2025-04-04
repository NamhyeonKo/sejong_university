//  hello.s
.file   "hello.c"
.section    .rodata
.LC0:
    .string "hello!\n"
.text
.global main
.type   main, @function
main:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $.LC0, %edi
    call    printf
    movl    $0, %eax
    popq    %rbp
    ret