#pragma once

#include <thread>
#include <iostream>
#include <vector>
#include <numeric>
#include <future>

#include <stdexcept>
#include <string>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
using namespace  std;
class CCircleBuf_
{
public:
	CCircleBuf_() {
		m_state = false;
		m_buf = NULL;
		m_size = 0;
		m_in = 0;
		m_out = 0;
	}
	~CCircleBuf_() {
		if (m_buf != NULL)
		{
			delete[] m_buf;
		}
		m_state = false;
		m_size = 0;
		m_in = 0;
		m_out = 0;
	}
public:
	bool Initial(uint32_t size)
	{
		if (m_state == true) {
			printf("it's already initial!\n");
			return false;
		}
		if (size & (size - 1)) {
			printf("buffer size must be 2 Power\n");
			return false;
		}
		m_size = size;
		m_in = m_out = 0;
		m_buf = new int8_t[size];
		if (m_buf == NULL)
		{
			printf("CCircleBuf allocate mem failed!\n");
			return false;
		}
		memset(m_buf, 0, sizeof(size));
		m_state = true;
		return true;
	}
	uint32_t fifo_read(int8_t *buf, uint32_t len)
	{
		uint32_t node_len = 0;
		if (0 == GetUsedlen())
		{
			return 1;
		}
		len = Read(buf, len);
		//优化，如果数据读取完毕则重置m_in，m_out
		if (0 == GetUsedlen())
		{
			m_in = m_out = 0;
		}
		return len;
	}
	uint32_t fifo_write(int8_t *buf, uint32_t len)
	{
		if (GetUsedlen() + len > m_size)
		{
			printf("fifo_write the buf is overflow!\n");
			return 1;
		}
		//写入数据内容
		len = Write(buf, len);
		return len;
	}
	bool Reset()
	{
		m_in = m_out = 0;
	}
	uint32_t GetUsedlen()
	{
		return m_in - m_out;
	}
protected:
	uint32_t Read(int8_t *buf, uint32_t len)
	{
		//获取使用空间大小    
		uint32_t used_size = GetUsedlen();
		len = min(len, used_size);
		uint32_t lelf = min(len, (uint32_t)(m_size - (m_out &(m_size - 1))));
		memcpy(buf, m_buf + (m_out & (m_size - 1)), lelf);
		memcpy(buf + lelf, m_buf, len - lelf);
		m_out += len;
		return len;
	}
	uint32_t Write(int8_t *buf, uint32_t len)
	{
		//获取使用空间大小    
		uint32_t used_size = GetUsedlen();
		len = min(len, (uint32_t)(m_size - used_size));
		uint32_t lelf = min(len, (uint32_t)(m_size - (m_in &(m_size - 1))));
		memcpy(m_buf + (m_in &(m_size - 1)), buf, lelf);
		memcpy(m_buf, buf + lelf, len - lelf);
		m_in += len;
		return len;
	}
private:
	bool			m_state;
	int8_t			*m_buf;
	uint32_t		m_size;
	uint32_t		m_in;
	uint32_t		m_out;
};


/*#############################################################################*/
class CCircleBuf
{
public:
	CCircleBuf()
	{
		m_state = false;
	}
	~CCircleBuf()
	{

	}
public:
	int    Initial(int size)
	{
		if (m_state == true)
		{
			printf("it's already initial!\n");
			return -1;
		}
		if (size & (size - 1))
		{
			printf("buffer size must be 2 Power\n");
			return -1;
		}
		m_size = size;
		m_in = m_out = 0;
		m_buf = new unsigned char[size];
		memset(m_buf, 0, sizeof(size));
		m_state = true;
		return 0;
	}
	int Destroy()
	{
		return 0;
	}
	unsigned short fifo_read(char *buf, unsigned short len)
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		unsigned short node_len = 0;
		if (0 == GetUsedlen())
		{
			printf("********** there is no data to read!\r\n");
			return 0;
		}
		//读取数据长度
		if (0 == Read((char*)&node_len, sizeof(node_len)))
		{
			printf("********** get node_len faild!\r\n");
			return 0;
		}
		//读取数据内容
		if (len < node_len)
		{
			printf("********** buf size is small!\r\n");
			return 0;
		}

		if (0 == Read(buf, node_len))
		{
			printf("********** get node_content faild!\r\n");
			return 0;
		}
		//优化，如果数据读取完毕则重置m_in，m_out
		if (0 == GetUsedlen())
		{
			m_in = m_out = 0;
		}
		return len;
	}
	unsigned short fifo_write(char *buf, unsigned short len)
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		if (GetUsedlen() + sizeof(len) + len > m_size)
		{
			printf("********** the room of buf is full!\r\n");
			return 0;
		}
		//写入文件长度
		Write((char*)&len, sizeof(len));
		//写入数据内容
		Write(buf, len);
		return len;
	}
protected:
	unsigned short Read(char *buf, unsigned short len)
	{
		//获取使用空间大小    
		unsigned short used_size = GetUsedlen();
		len = min(len, used_size);
		unsigned short lelf = min(len, (unsigned short)(m_size - (m_out &(m_size - 1))));
		memcpy(buf, m_buf + (m_out & (m_size - 1)), lelf);
		memcpy(buf + lelf, m_buf, len - lelf);
		m_out += len;
		return len;
	}
	unsigned short Write(char *buf, unsigned short len)
	{
		//获取使用空间大小    
		unsigned short used_size = GetUsedlen();
		len = min(len, (unsigned short)(m_size - used_size));
		unsigned short lelf = min(len, (unsigned short)(m_size - (m_in &(m_size - 1))));
		memcpy(m_buf + (m_in &(m_size - 1)), buf, lelf);
		memcpy(m_buf, buf + lelf, len - lelf);
		m_in += len;
		return len;
	}
	unsigned short GetUsedlen()
	{
		return m_in - m_out;
	}
private:
	bool				m_state;
	unsigned char		*m_buf;
	unsigned short		m_size;
	unsigned short		m_in;
	unsigned short		m_out;
	std::mutex			m_mutex;
};

#ifdef WIN32
CCircleBuf gCircleBuf;
void ThreadRead()
{
	char temp[1024] = { '\0' };
	char buf[128] = { '\0' };
	while (1)
	{
		memset(temp, 0, sizeof(temp));
		memset(buf, 0, sizeof(buf));
		if (gCircleBuf.fifo_read(buf, sizeof(buf)) > 0)
		{
			sprintf_s(temp, "read data:%s\r\n", buf);
			OutputDebugString(temp);
		}
		//Sleep(1 * 1000);
	}
}


void ThreadWrite()
{
	srand(time(NULL));
	while (1)
	{
		char buf[128] = { '\0' };
		sprintf_s(buf, "(%d)", rand());
		OutputDebugString(buf);
		if (gCircleBuf.fifo_write(buf, strlen(buf)))
		{
			//写入失败休眠50ms
			Sleep(0);
		}
		//Sleep(1 * 1000);
	}
}
#endif // WIN32