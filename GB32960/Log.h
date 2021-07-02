#pragma once
#include <iostream>
#include <string.h>
#include <string>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include<shlobj.h>    //Òª¼Óshlobj.h
#include "Common.h"
using namespace std;

class CLog
{
public:
	static CLog &GetInstance()
	{
		static CLog instance;
		return instance;
	}
public:
	CLog();
	~CLog();
public:
	int Initialize();
	int Destroy();
public:
	void OutPutLog(const char * pszFormat, ...);
	void OutPutLogHex(unsigned char *buf, int len, char *func, int line);
private:
	char* GetCurTime();
	void Log(const string &log);
private:
	FILE *m_fd;
};