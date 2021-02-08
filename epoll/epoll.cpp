// TestEpoll.cpp : 定义控制台应用程序的入口点。
//



#ifdef _WIN32
#include "stdafx.h"
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif
#include <iostream>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <thread>
#include <mutex>
using namespace std;

#define MaxEvent 1000
#define MaxClient 1000
#define TimeOut 500

#ifndef WIN32
#define HANDLE int
#define SOCKET int
#define SOCKET_ERROR -1
#define INVALID_SOCKET (0xFFFFFFFF)
#pragma message("11111111111111111111111")
#endif 

typedef struct  tagServerInfo
{
	HANDLE h;
}ServerInfo,*LPServerInfo;

int OutPutMessage(const char *fomart,...)
{
	char buff[1024] = {'\0'};
	va_list ap;
	va_start(ap,fomart);
	int ilen = vsnprintf(buff, sizeof(buff), fomart, ap);
	va_end(ap);
	printf(buff);
	return ilen;
}

#define OUTC_TRACE(x) OutPutMessage("[Epoll]%s %s %d %s\n",__FILE__,__FUNCTION__,__LINE__,x)
#ifdef _WIN32
#define OUTC_GetLastError(x) OutPutMessage("[Epoll]%s %s %d Failed:%d,syserr:%d\n",__FILE__,__FUNCTION__,__LINE__,x,GetLastError())
#else
#define OUTC_GetLastError(x) OutPutMessage("[Epoll]%s %s %d Failed:%d syserr:%d %s\n",__FILE__,__FUNCTION__,__LINE__,x,errno,strerror(errno))
#endif

int Close(HANDLE h)
{
	if (INVALID_SOCKET != h)
	{
#ifdef _WIN32
		shutdown(h,both);
		closesocket(h);
#else
		shutdown(h,SHUT_RDWR);
		close(h);
#endif
	}
}

class CEvent
{
public:
	CEvent()
	{
		Destory();
	}
	~CEvent()
	{
		Destory();
	}
	int Destory()
	{
		m_count = 0;
		m_hSocket = NULL;
	}
	int SetSocket(HANDLE h)
	{
		m_hSocket = h;
		return 0;
	}
	int GetSocket(HANDLE &h)
	{
		h = m_hSocket;
		return 0;
	}
	int GetState()
	{
		if (NULL != m_hSocket)
		{
			return 0;
		}
		return 1;
	}
	int MsgProcess()
	{
		char buff[1024] = {'\0'};
		int len = recv(m_hSocket, buff,sizeof(buff),0);
		if (len <= 0)
		{
			OUTC_TRACE("socket:%d ,client has close!");
			OUTC_GetLastError(m_hSocket);
			Close(m_hSocket);
		}
		else
		{
			if (send(m_hSocket, buff, strlen(buff), 0) <= 0)
			{
				OUTC_GetLastError(m_hSocket);
				Close(m_hSocket);
			}
			OUTC_TRACE(buff);
		}		
		return len;
	}
protected:
private:
	int m_count;
	HANDLE m_hSocket;
};
template<class T,int num>
class CResourceManager
{
public:
	CResourceManager()
	{
		Destory();
	}
	~CResourceManager()
	{
		Destory();
	}
	int Destory()
	{
		for (int i = 0; i<num; i++)
		{
			m_bIsIdle[i] = true;
		}
	}
	T& operator [](int index)
	{
		return m_Resource[index];
	}
	int InsertResource(int &index)
	{
		int i;
		for (i = 0; i<num; i++)
		{
			if (m_bIsIdle[i] == true)
			{
				m_bIsIdle[i] = false;
				index = i;
				break;
			}
		}
		if (i == num)
		{
			return 1;
		} 
		else
		{
			return 0;
		}
	}
	int RemoveResource(int index)
	{
		if (index <0 || index >num)
		{
			return 1;
		}
		if (m_bIsIdle[index] == false)
		{
			//删除资源时，清理数据
			m_Resource[index].Destory();
			m_bIsIdle[index] = true;
		}
		return 0;
	}

protected:
private:
	T m_Resource[num];
	bool m_bIsIdle[num];
};

class CEpoll
{
public:
	CEpoll()
	{
		m_bstate = false;
	}
	~CEpoll()
	{
		m_bstate = false;
	}
	int start()
	{
		if (m_bstate)
		{
			OUTC_TRACE("CEpoll has already start!");
			return 0;	
		}
		m_bstate = true;
		m_epollfd = epoll_create(MaxClient);
		if (-1 == m_epollfd)
		{
			OUTC_TRACE("Create epoll failed!");
		}
		std::thread(ProcessTask, this).detach();
// 		pthread_t pid;
//  		int ret = pthread_create(&pid, NULL, ProcessTask, this);
// 		if (0 != ret || 0 == pid)
// 		{
// 			OUTC_TRACE("Create Thread failed!\n");
// 		}
		return 0;
	}
	static void *ProcessTask(void *lparam)
	{
		CEpoll *epoll = (CEpoll*)lparam;
		OUTC_TRACE("ProcessTask is called!\n");
		epoll->RunTask();
	}
	int stop()
	{
		m_bstate =false;
		close(m_epollfd);
	}
	//EPOLL_CTL_ADD：注册新的fd到epfd中；
	//EPOLL_CTL_MOD：修改已经注册的fd的监听事件；
	//EPOLL_CTL_DEL：从epfd中删除一个fd；
	//注册
	int Insert(HANDLE h)
	{
		int index = -1;
		if (0 != m_EventManager.InsertResource(index))
		{
			OUTC_TRACE("Resource is running out!");
			return 0;
		}
		printf("Insert index = %dmsocket = %d\n",index,(int)h);
		m_EventManager[index].SetSocket(h);
		struct epoll_event ev;
		ev.events = EPOLLIN;
		//用户数据 date是union类型
		//ev.data.fd = (int)h;
		ev.data.ptr = (void*)(&m_EventManager[index]);
		if (epoll_ctl(m_epollfd, EPOLL_CTL_ADD, h,&ev) == -1)
		{
			OUTC_TRACE("insert h into epoll_ctl failed!");
		}
	}
	int Remove(HANDLE h)
	{
		HANDLE hSocket;
		for (int i=0; i< MaxEvent; i++)
		{
			m_EventManager[i].GetSocket(hSocket);
			if (hSocket == h)
			{
				struct epoll_event ev;
				if (-1  == epoll_ctl(m_epollfd, EPOLL_CTL_DEL, h, &ev))
				{
					OUTC_GetLastError(h);
				}
				m_EventManager.RemoveResource(i);
				break;
			}
		}
		return 0;
	}
	int Modify(HANDLE h)
	{

	}
	int RunTask()
	{
		struct epoll_event EventSet[MaxClient];
		OUTC_TRACE("RunTask is called!\n");
		while(m_bstate)
		{
			int nfd = epoll_wait(m_epollfd, EventSet,MaxClient, TimeOut);
			if ( -1 == nfd)
			{
				OUTC_TRACE("epoll_wait error, exit\n");  
				break;  
			}
			else if(0 == nfd)
			{
				//OUTC_TRACE("epoll_wait has already timeout!\n");
			}
			else 
			{  
				for (int i=0;i<nfd;i++)
				{
					if (EventSet[i].events & EPOLLIN)
					{
						CEvent *event = (CEvent *)EventSet[i].data.ptr;
						int ret = event->MsgProcess();
						/*close的文件描述符会在epoll set中被自动remove*/
						if (ret <=0)
						{
							OUTC_TRACE("release resource!");
							HANDLE hSocket;
							event->GetSocket(hSocket);
							Remove(hSocket);
						}
					}
				}
			}
		}
		OUTC_TRACE("RunTask is over!\n");
	}
protected:
private:
	CResourceManager<CEvent,MaxEvent> m_EventManager;
	int m_epollfd; 
	bool m_bstate;
};
CEpoll g_Epoll;

void *ProcessCon(void *lparam)
{
	ServerInfo *server = (ServerInfo *)lparam;
	sockaddr_in clientaddr;
	socklen_t len = sizeof(clientaddr);
	printf("sServer hScoket:%d\n",server->h);
	while (1)
	{
		memset(&clientaddr,0,len);
		HANDLE hClient = accept(server->h,(sockaddr *)&clientaddr,&len);
		if (INVALID_SOCKET != hClient)
		{
			printf("client IP:%s,Port:%d\n",inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port));
			g_Epoll.Insert(hClient);
		}	
		printf("sServer hScoket:%d\n",server->h);
	}
}

int main()
{
	//初始化
	OUTC_TRACE("***************Start!\n");
	
	//启动Epoll
	g_Epoll.start();

	sockaddr_in sock_addr1,sock_addr2;
	socklen_t s1,s2;
	s1=sizeof(sock_addr1);
	s2=sizeof(sock_addr2);
	memset(&sock_addr1,0x00,s1);
	memset(&sock_addr2,0x00,s2);
	sock_addr1.sin_port=htons(8888);
	sock_addr1.sin_family=AF_INET;
	sock_addr1.sin_addr.s_addr=htonl(INADDR_ANY);
	//创建套接字
	int sockhst=socket(AF_INET,SOCK_STREAM,0);
	if (sockhst==-1)
	{
		printf("socket() failed!");
		return 0;
	}
	//绑定端口和地址
	int ivalue = 1;
	::setsockopt(sockhst, SOL_SOCKET, SO_REUSEADDR,(char*)&ivalue,sizeof(ivalue));
	if (bind(sockhst,(struct sockaddr *)&sock_addr1,s1)==-1)
	{
		printf("bind() failed!");
		return 0;
	}
	//监听
	if (listen(sockhst,5)==-1)
	{
		printf("listen() failed!");
		return 0;
	}
	//等待连接
	while(1)
	{
		int sockcld=accept(sockhst,(struct sockaddr *)&sock_addr2,&s2);
		if (sockcld==-1)
		{
			printf("accept() failed!");
			OUTC_GetLastError(sockcld);
			return 0;
		}
		else
		{
			printf("socket:%d, client IP:%s,Port:%d\n",sockcld,inet_ntoa(sock_addr2.sin_addr),ntohs(sock_addr2.sin_port));
			g_Epoll.Insert(sockcld);
			cout<<"being connected!"<<endl;
		}

	}	
	close(sockhst);

	printf("Program is Over\n");
	return 0;
}

