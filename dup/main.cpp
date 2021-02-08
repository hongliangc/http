#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main()
{
    int fd = 0;
    char *buf="This is a test!!!!\n";
	FILE *oldfd = fopen("mine.txt", "wb+");
    if(oldfd == NULL)
    {
        printf("open error\n");
        exit(-1);
    }
	int tmp  = fileno(oldfd);
	int fdstdout = fileno(stdout);
	fd = dup2(tmp, fdstdout);
	if (fd == -1)
	{
		printf("dup2 out fail\n");
		exit(-1);
	}
	int fdstderr = fileno(stderr);
	fd = dup2(tmp, fdstderr);
	if (fd == -1)
	{
		printf("dup2 err fail\n");
		exit(-1);
	}
	
	printf("test printf 1\n");
    printf("dup2的返回值：%d\n",fd);

	fprintf(stderr, buf);
	fprintf(stdout, "test stdout 1\n");
	fprintf(stderr, "test stderr 1\n");
	{
		FILE *newfd = fopen("mine1.txt", "wb+");
		if (newfd == NULL)
		{
			printf("111open error\n");
			exit(-1);
		}
		int tmp = fileno(newfd);
		int fdstdout = fileno(stdout);
		fd = dup2(tmp, fdstdout);
		if (fd == -1)
		{
			printf("111dup2 out fail\n");
			exit(-1);
		}
		int fdstderr = fileno(stderr);
		fd = dup2(tmp, fdstderr);
		if (fd == -1)
		{
			printf("111dup2 err fail\n");
			exit(-1);
		}

		printf("t111est printf 1\n");
		printf("111dup2的返回值：%d\n", fd);

		fprintf(stderr, buf);
		fprintf(stdout, "111test stdout 1\n");
		fprintf(stderr, "111test stderr 1\n");
		fflush(newfd);
		fclose(newfd);
	}
	fflush(oldfd);
	fclose(oldfd);
	return 0;
}