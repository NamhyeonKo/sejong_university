/* 21011724 고남현 */
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

int main(){
    int fd[2]; /* fd[0]: 읽기, fd[1]: 쓰기 */
    pid_t pid;

    char read_buffer[25];   /* 읽기 버퍼 선언, 크기 25 버퍼 */

    if (pipe(fd) == -1){    /* 파이프 생성 */
        fprintf(stderr, "Pipe error");  /* 파이프 생성 에러 발생시 에러 반환 */
        return 1;
    }

    pid = fork();   /* 새로운 프로세스 생성 */

    if (pid > 0) {  /* 부모 프로세스 */
        close(fd[0]); /* 사용 안 할 종단 닫기(읽기 닫기) */
        write(fd[1], "Greetings", strlen("Greetings")); /* Greetings 적기 */
    } else if (pid == 0){    /* 자식 프로세스 */
        close(fd[1]); /* 사용 안 할 쓰기 종단 닫기 */
        read(fd[0], read_buffer, sizeof(read_buffer));  /* 메시지 가져오기(읽기 버퍼에 옮기기) */
        printf("child read %s\n", read_buffer); /* 읽은 메시지 출력 */
    } else {    /*  fork() 실패 시 에러 */
        printf(stderr, "Fork Failed");
        return 1;
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