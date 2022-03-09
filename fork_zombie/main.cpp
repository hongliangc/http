#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//#include <malloc.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <unistd.h>
#include <fcntl.h>

#include <signal.h>
#include <time.h>

void mysleep(int sec)
{
	time_t start = time(NULL), elapsed = 0;
	while (elapsed < sec)
	{
		sleep(sec - elapsed);
		elapsed = time(NULL) - start;
	}
}

void signal_handler(int signo)
{
	if (signo == SIGCHLD)
	{
		pid_t pid;
		mysleep(5);
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
		{
			printf("SIGCHLD pid %d\n", pid);
		}
	}
}

int main(int argc, char **argv)
{
	signal(SIGCHLD, signal_handler);
	while (1)
	{
		pid_t pid = fork();
		if (pid > 0)
		{
			// parent process
			mysleep(5);
		}
		else if (pid == 0)
		{
			// child process
			printf("child pid %d\n", getpid());
			return 0;
		}
		else
		{
			fprintf(stderr, "fork error\n");
			return 2;
		}
	}
}