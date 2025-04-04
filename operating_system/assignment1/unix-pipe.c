//  21011724 고남현
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

int main(){
    int fd[2]; // fd[0]: 읽기, fd[1]: 쓰기

    pipe(fd);
    
    pid_t pid;

    pid = fork();

    if (pid > 0) {  // 부모 프로세스
        close(fd[0]); // 읽기 닫기
        write(fd[1], "Greetings", strlen("Greetings"));
    } else {    // 자식 프로세스
        close(fd[1]); // 쓰기 닫기
        char buffer[100];
        read(fd[0], buffer, sizeof(buffer));
        printf("child read %s\n", buffer);
    }
    
    return 0;
}

/*
 unix-pipe.c 설명
 
 The purpose of the program: to create a pipe and fork a child process in C.
 The program constructs a pipe to be shared between the child and parent process.
 If we are the parent process, we write the message to the array buffer fd.
 If we are the child process, we read from the READ END of the buffer fd, and print out that the child read the message from the buffer.
 The program output is the following:

 child read Greetings
 */