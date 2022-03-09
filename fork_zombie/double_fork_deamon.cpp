#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

void has_tty()
{
    int tty = open("/dev/tty", O_RDWR);
    if (tty > 0)
    {
        printf("process %d has tty %d\n", getpid(), tty);
    }
    else
    {
        printf("process %d has no tty\n", getpid());
    }
}

int main(void)
{
    pid_t pid;

    printf("main process pid:%d, ppid:%d\n", getpid(), getppid());
    if ((pid = fork()) < 0)
    {
        printf("fork error\n");
        exit(1);
    }
    else if (pid == 0)
    {
        printf("first child pid:%d, ppid:%d\n", getpid(), getppid());
        // first child
        has_tty(); //拥有tty
        setsid();
        has_tty(); //已经断开tty

        if ((pid = fork()) < 0)
        {
            printf("fork error\n");
            exit(1);
        }
        else if (pid > 0)
        {
            // exit first child
            printf("first child pid:%d exit!\n", getpid());
            exit(0);
        }
        printf("second child pid:%d, ppid:%d\n", getpid(), getppid());

        has_tty(); //已经断开tty
        sleep(2);
        printf("second child ppid = %d\n", getppid());

        sleep(1000);
        exit(0);
    }

    // 清理first child，保证first child不会成为僵尸进程
    if (waitpid(pid, NULL, 0) != pid)
    {
        printf("waitpid error\n");
        exit(1);
    }
    printf("main process exit\n");

    exit(0);
}