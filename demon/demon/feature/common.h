#pragma once
#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <map>
#include <stdarg.h>
using namespace std;

typedef char                CHAR;
typedef signed char         INT8;
typedef unsigned char       UCHAR;
typedef unsigned char       UINT8;
typedef unsigned char       BYTE;
typedef short               SHORT;
typedef signed short        INT16;
typedef unsigned short      USHORT;
typedef unsigned short      UINT16;
typedef unsigned short      WORD;
typedef int                 INT;
typedef signed int          INT32;
typedef unsigned int        UINT;
typedef unsigned int        UINT32;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned long       DWORD;
typedef __int64             LONGLONG;
typedef __int64             LONG64;
typedef signed __int64      INT64;
typedef unsigned __int64    ULONGLONG;
typedef unsigned __int64    DWORDLONG;
typedef unsigned __int64    ULONG64;
typedef unsigned __int64    DWORD64;
typedef unsigned __int64    UINT64;
typedef int					BOOL;


//调用约定
#define STDCALL		__stdcall
#define CDECCALL	__cdecl

#if defined(_WIN32) || defined(_WIN64)
#define OS_WIN
#else
#define OS_LINUX
#endif

#if defined(OS_WIN)
#define _EXPORT_ __declspec(dllexport)
#define _IMPORT_ __declspec(dllimport)
#elif defined(OS_LINUX)
#define _EXPORT_
#define _IMPORT_
#endif

/** @brief 返回值(成功)																	*/
#define RET_SUCCESS				(0)

/** @brief 返回值(失败)																	*/
#define RET_FAIL				(-1)

#define FREE_PTR(x)										\
{														\
	if (NULL != x)										\
	{													\
		delete x;										\
		x = NULL;										\
	}													\
}

#define FREE_ARR(x)										\
{														\
	if (NULL != x)										\
	{													\
		delete[] x;										\
		x = NULL;										\
	}													\
} 

class Log {
public:
	static void Printf(const char* fmt, ...)
	{
		char tmp[1024] = { '\0' };
		char buff[2048] = { '\0' };
		time_t t = time(NULL);
		struct tm * cur = localtime(&t);
		va_list args;
		va_start(args, fmt);
		vsnprintf(tmp, sizeof(tmp), fmt, args);
		va_end(args);
		sprintf(buff, "%04d-%02d-%02d %02d:%02d:%02d %s err:%d,%s\n", cur->tm_year + 1900, cur->tm_mon + 1, cur->tm_mday, cur->tm_hour, cur->tm_min, cur->tm_sec, \
			tmp);
		printf(buff);
	}
	static void ePrintf(const char* fmt, ...)
	{
		char tmp[1024] = { '\0' };
		char buff[2048] = { '\0' };
		time_t t = time(NULL);
		struct tm * cur = localtime(&t);
		va_list args;
		va_start(args, fmt);
		vsnprintf(tmp, sizeof(tmp), fmt, args);
		va_end(args);
		sprintf(buff, "%04d-%02d-%02d %02d:%02d:%02d %s err:%d,%s\n", cur->tm_year + 1900, cur->tm_mon + 1, cur->tm_mday, cur->tm_hour, cur->tm_min, cur->tm_sec, \
			tmp, errno, strerror(errno));
		printf(buff);
	}
};

#define _HTONS(x)	((((UINT16)(x) & 0xff00 )>> 8) | (((UINT16)(x) & 0xff) << 8))
#define _HTONL(x)	(((UINT32)(x) >> 24) | (((UINT32)(x) & 0xff0000) >> 8) | (((UINT32)(x) & 0xff) << 24) | (((UINT32)(x) & 0xff00) << 8))			


//日志输出
#define LOG CLog::Print
#define LOGERR(x) CLog::ePrint



//动态库导出宏定义
#ifdef _FEATURE
#define FEATURE_API _EXPORT_
#else
#define FEATURE_API _IMPORT_
#endif

//定义出参还是入参宏标识
#define _In
#define _Out