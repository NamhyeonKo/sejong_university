/* 21011724 고남현 */
#include <pthread.h>
#include <stdio.h>

int sum;    /* 스레드간 공유될 데이터 */
void *runner(void *param);   /* 스레드가 호출할 함수 */

int main(int argc, char *argv[]){
    pthread_t tid;  /* 스레드 id */
    pthread_attr_t attr;    /* 스레드 속성 */

    if (argc != 2){
        fprintf(stderr, "main함수 인자 개수 에러(인자 2개 입력 받아야함)");
        return -1;
    }
    if (atoi(argv[1]) < 0){
        fprintf(stderr, "입력 에러 (양수 입력 받아야함)");
        return -1;
    }

    pthread_attr_init(&attr);   /* 기본 속성 가져오기 */
    pthread_create(&tid, &attr, runner, argv[1]);   /* 스레드 생성 */
    pthread_join(tid, NULL);    /* 스레드 종료 기다리기 */

    printf("sum = %d\n", sum);

    return 0;
}

void *runner(void *param){  /* 스레드가 실행할 함수 */
    int i, upper = atoi(param); /* 파라미터 정수로 바꿔주기 */
    sum = 0;

    for (i = 1; i <= upper; i++) sum += i;

    pthread_exit(0);    /* 스레드 종료 */
}

/*
 thrd-posix.c 설명
 
 The purpose of the program: to work with the Pthread library in C to create a pthread that will execute some work.
 The work in this program will sum all of the integers from 1 to the supplied argument. 
 The program initiates, creates, and joins the pthread created, and then prints the sum. 
 In the pthread create method, we assign the ”work” to be done to the pthread, which is the runner method, and forwards the argument supplied to the program in pthread create.
 The program output is the following (with integer parameter 2000):

 sum = 2001000
*/