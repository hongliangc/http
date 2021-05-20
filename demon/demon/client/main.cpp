#include <iostream>
#include <stdio.h>
#include <string>
#include <errno.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#if 1
int main()
{
	WSADATA wsaVersion;
	WSAStartup(0x0202, &wsaVersion);
	try
	{
		//m_sgmwNetwork->connectServer("113.17.111.183", 10004, true);
		int err = -1;
		char buff[1024] = { '\0' };
		sockaddr_in remote_addr, local_addr;
		size_t s1 = sizeof(remote_addr);
		size_t s2 = sizeof(local_addr);
		memset(&remote_addr, 0x00, s1);
		memset(&local_addr, 0x00, s2);
		local_addr.sin_port = htons(1122);
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = INADDR_ANY;

		remote_addr.sin_port = htons(8888);
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_addr.s_addr = inet_addr("10.1.11.203");
		//创建套接字
		int cfd = socket(AF_INET, SOCK_STREAM, 0);
		if (cfd == -1)
		{
			printf("socket() failed! syserr:%d %s\n", errno, strerror(errno));
			err = GetLastError();
			return -1;
		}
		//绑定端口和地址
		int ivalue = 1;
		::setsockopt(cfd, SOL_SOCKET, SO_REUSEADDR, (char*)&ivalue, sizeof(ivalue));
		if (bind(cfd, (struct sockaddr *)&local_addr, s1) == -1)
		{
			printf("bind() failed!");
			err = GetLastError();
			return -1;
		}
		if (connect(cfd, (struct sockaddr *)&remote_addr, s1) == -1)
		{
			printf("connect() failed! syserr:%d %s\n", errno, strerror(errno));
			err = GetLastError();
			return -1;
		}
		sprintf(buff, "client fd:%d\n", cfd);
		if (send(cfd, buff, strlen(buff), 0) <= 0)
		{
			printf("send() failed! syserr:%d %s\n", errno, strerror(errno));
			err = GetLastError();
			return -1;
		}
	}
	catch (std::exception &e) // catching by value is OK (smart copying)
	{
		cout << "e:" << e.what();
	}
	system("pause");
	return 0;
}
#else
int main()
{
	char buff[4096] = { '\0' };
	char* p = NULL;
	int read_header_status = 0;
	int flag = 0;
	int recv_len = 0;
	int len = 1;
	FILE *fd = NULL;
	fopen_s(&fd, "111.raw", "rb");
	FILE *fd1 = NULL;
	fopen_s(&fd1, "22.tar.gz", "wb+");
	if (fd != NULL)
	{
		p = buff;
		while (!feof(fd))
		{
			recv_len = fread(p, 1, 1, fd);
			if (recv_len > 0)
			{
				if (1 == recv_len)
				{
					switch (read_header_status)
					{
					case 0:
						if (*p == '\r')
							read_header_status = 1;
						break;
					case 1:
						if (*p == '\n'){
							printf("header:%s\n", buff);
							memset(buff, 0x00, sizeof(buff));
							p = buff;
							read_header_status = 2;
						}
						else
							read_header_status = 0;
						break;
					case 2:
						if (*p == '\r')
							read_header_status = 3;
						else
							read_header_status = 0;
						break;
					case 3:
						if (*p == '\n') {
							printf("header:%s\n", buff);
							memset(buff, 0x00, sizeof(buff));
							p = buff;
							printf("find body\n", buff);
							flag++;
							if (flag == 1)
							{
								read_header_status = 0;
							}
							if (flag == 2)
							{
								int offset = 0;
								while (!feof(fd))
								{
									memset(buff + offset, 0x00, sizeof(buff) - offset);
									recv_len = fread(buff + offset, 1, sizeof(buff) - offset, fd);
									if (recv_len > 0)
									{
										if (recv_len > 2)
										{
											//offset = 2;
											fwrite(buff, 1, recv_len - offset, fd1);
											memcpy(buff, buff + recv_len - offset, offset);
											fflush(fd1);
										}
										else if(recv_len == 2)
										{
											break;
										}
										else  if (recv_len == 1)
										{
											fwrite(buff, 1, 1, fd1);
											break;
										}
									}
									else
									{
										printf("getlasterror:%d\n", errno);
									}
								}
								printf("last bytes:0x%0x,0x%0x\n", buff[0], buff[1]);
								goto _parse_header;
							}
							//goto _parse_header;
						}
						else
							read_header_status = 0;
						break;
					default:
						read_header_status = 0;
						break;
					}
					if (read_header_status != 2)
					{
						p++;
					}
				}
				else if (0 == recv_len)
				{
					printf("recv_len is 0");
					goto _error;
				}
			}
		}
	}
	fclose(fd);
	fclose(fd1);
_parse_header:
_error:
	return 0;
}
#endif