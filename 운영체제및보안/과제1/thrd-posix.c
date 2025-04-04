//  21011724 고남현
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>


/*
 thrd-posix.c 설명
 
 The purpose of the program: to work with the Pthread library in C to create a pthread that will execute some work.
 The work in this program will sum all of the integers from 1 to the supplied argument. 
 The program initiates, creates, and joins the pthread created, and then prints the sum. 
 In the pthread create method, we assign the ”work” to be done to the pthread, which is the runner method, and forwards the argument supplied to the program in pthread create.
 The program output is the following (with integer parameter 2000):

 sum = 2001000
*/