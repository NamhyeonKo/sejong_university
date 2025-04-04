//  21011724 고남현
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

int main(){
    pid_t pid;

    pid = fork();

    if (pid < 0){   //  fork() 실패
        printf(stderr, "Fork Failed");
        return 1;
    } else if(pid == 0){    //  자식 프로세스
        printf("I am the child %d\n", pid);
        execlp("/bin/ls","ls",NULL);
    } else{ //  부모 프로세스
        printf("I am the parent %d\n", pid);
        wait(NULL);
        printf("Child Complete");
    }

    return 0;
}

 /*
 newproc-posix.c 설명
 
 The purpose of the program:
 to fork a process and create a child, then print the output.
 If the process is the child (with pid == 0),
 then it will print the files in the current directory (with the execlp(”/bin/ls”,”ls”,NULL); command).
 A program output can be the following (Note: the lines 1, 2, and 3 can be different order):
 I am the child 0
 I am the parent 23890
 newproc-posix.c posix
 Child Complete
 */