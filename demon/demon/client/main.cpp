#include <iostream>
#include <stdio.h>
#include <string>
#include <errno.h>
using namespace std;

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