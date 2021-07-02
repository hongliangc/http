#include "Log.h"


#define _LOG2SCEEN_		1
#define _LOG_PATH_			"C:\\UpgradeKit\\"


CLog::CLog()
{
	m_fd = NULL;
}
CLog::~CLog()
{
	if (NULL != m_fd)
	{
		fclose(m_fd);
		m_fd = NULL;
	}
}

int CLog::Initialize()
{
	errno_t err;
	if (NULL != m_fd)
		return RET_SUCCESS;
	//´´½¨Ä¿Â¼
	char filename[248] = { 0 };
	time_t local;
	struct tm *struTM = NULL;
	time(&local);
	err = localtime_s(struTM,&local);
	if (0 != err)
	{
		sprintf_s(filename, "%s%04d-%02d-%02d.log", _LOG_PATH_, struTM->tm_year + 1900, struTM->tm_mon + 1, struTM->tm_mday);
	}
	int ret = SHCreateDirectoryEx(NULL, _LOG_PATH_, NULL);
	if (ret == ERROR_ALREADY_EXISTS || ret == ERROR_SUCCESS)
	{
		errno_t err = fopen_s(&m_fd,filename, "ab+");
		if (0 != err)
		{
			LOGSYSERR;
		}
	}
	else
	{
		printf("create file failed!\n");
		return RET_FAIL;
	}
	return RET_SUCCESS;
}

int CLog::Destroy()
{
	return RET_SUCCESS;
}

void CLog::Log(const string &log)
{
	if (NULL != m_fd && log.empty() == false)
	{
		fwrite(log.c_str(), 1, log.length(), m_fd);
		fflush(m_fd);
	}
}
void CLog::OutPutLog(const char * pszFormat, ...)
{
	char szBuf[1024] = {0};
	char temp[2048] = { 0 };
	va_list ap;
	va_start(ap, pszFormat);
	vsnprintf(szBuf, sizeof(szBuf), pszFormat, ap);
	va_end(ap);

// 	char curTime[64] = {0};
// 	time_t local;
// 	struct tm *struTM = NULL;
// 	time(&local);
// 	struTM = localtime(&local);
// 	if (NULL != struTM)
// 	{
// 		sprintf_s(curTime,"%04d-%02d-%02d %02d:%02d:%02d",struTM->tm_year + 1900, struTM->tm_mon + 1, struTM->tm_mday, struTM->tm_hour, struTM->tm_min, struTM->tm_sec);
// 	}

	sprintf_s(temp, "%s %s", GetCurTime(), szBuf);
#if _LOG2SCEEN_
	printf(temp);
#else
	OutputDebugString(temp);
#endif
	Log(temp);
}


void CLog::OutPutLogHex(unsigned char *buf, int len,char *func, int line)
{
	char temp[128] = {0};
	sprintf_s(temp,"%s [%s %d] len:%d data :",GetCurTime(),func,line,len);
#if _LOG2SCEEN_
	printf(temp);
#else
	OutputDebugString(temp);
#endif
	Log(temp);
	for (int i = 0; i < len; i++)
	{
		sprintf_s(temp,"%02x ",buf[i]);
#if _LOG2SCEEN_
		printf(temp);
#else
		OutputDebugString(temp);
#endif
		Log(temp);
		//if((i + 1) % 8 == 0 || i == len -1)
		//	printf("\n");
	}
#if _LOG2SCEEN_
	printf("\n");
#else
	OutputDebugString("\n");
#endif
	Log("\n");
}


char* CLog::GetCurTime()
{
	static char curTime[128] = { 0 };
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(curTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	return curTime;
}