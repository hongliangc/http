#pragma once
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string.h>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <queue>
#include <mutex>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <random>
#include <limits>
#include <condition_variable>
#ifndef _WIN32
#include <sys/time.h>  
#include <unistd.h>
#endif

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


#define logTypeCommon 0
#define logTypeErr 1


/*! ��ʽ������*/
template<typename ...Args>
static std::string format(const std::string &format_, Args ...args)
{
	unsigned int len = std::snprintf(nullptr, 0, format_.c_str(), args...) + 1;
	std::unique_ptr<char[]> buf(new(std::nothrow) char[len]);
	if (!buf)
		return std::string("");
	std::snprintf(buf.get(), len, format_.c_str(), args...);
	return std::string{ buf.get(), len};
}

/*!��־��ʽ��*/
template<class ...Args>
void Log(int type, char *format_, Args... args)
{
	auto  data = format(format_, args...);
	static std::mutex mutex;
	std::unique_lock<std::mutex> lock(mutex);

	time_t t = time(NULL);
	struct tm  cur;
#ifdef _WIN32
	localtime_s(&cur, &t);
#else
	localtime_r(&t, &cur);
#endif
	std::string log = format("%04d-%02d-%02d %02d:%02d:%02d %s\n", cur.tm_year + 1900, cur.tm_mon + 1, cur.tm_mday, cur.tm_hour, cur.tm_min, cur.tm_sec, data.data());
	printf(log.data());
}

#define _LOG(type,...)  Log(type,__VA_ARGS__) 


#include "openssl/aes.h"
namespace _utility
{
	class CUtility
	{
	public:
		static std::string Encrypt(unsigned char* data, unsigned int len, unsigned char* key)
		{
#if 0
			auto out_len = len;
			unsigned char *output = new unsigned char[out_len];
#else
			auto out_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE)*AES_BLOCK_SIZE;//�������
			unsigned char *output = new unsigned char[out_len];
#endif
			AES_KEY aes_key;
			AES_set_encrypt_key(key, 128, &aes_key);
			for (unsigned int i = 0; i < len; i += AES_BLOCK_SIZE)
			{
				AES_ecb_encrypt(data + i, output + i, &aes_key, AES_ENCRYPT);
			}
			std::string str{ (char*)output, out_len };
			delete[] output;
			return std::move(str);
		}

		static std::string Decrypt(unsigned char* data, unsigned int len, unsigned char* key)
		{
#if 0
			auto out_len = len;
			unsigned char *output = new unsigned char[out_len];
#else
			auto out_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE)*AES_BLOCK_SIZE;//�������
			unsigned char *output = new unsigned char[out_len];
#endif
			AES_KEY aes_key;
			AES_set_decrypt_key(key, 128, &aes_key);
			for (unsigned int i = 0; i < len; i += AES_BLOCK_SIZE)
			{
				AES_ecb_encrypt(data + i, output + i, &aes_key, AES_DECRYPT);
			}
			std::string str{ (char*)output, out_len };
			delete[] output;
			return std::move(str);
		}

		/*! �ַ���ת����16����*/
		static std::string ToHex(const std::string& s, bool upper_case = true)
		{
			std::ostringstream ret;
			ret << std::hex << std::setfill('0');
			for (unsigned char c : s)
				ret << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << int(c);

			return ret.str();
		}

		//transform strings to hex
		static bool ConvertStr2Hex(const unsigned char *in, int ilen, std::string &out)
		{
			if (ilen == 0 || in == NULL)
			{
				return false;
			}
			std::stringstream ss;
			for (int i = 0; i < ilen; i++)
			{
				//�ַ�ת����16���ƴ����ss��
				ss << std::hex << (in[i] >> 4) << (in[i] & 0x0f);
			}
			ss >> out;
			return true;
		}
		//transform hex to strings
		static bool ConvertHex2Str(const unsigned char *in, int ilen, std::string &out)
		{
			if (ilen == 0 || ilen % 2 != 0 || in == NULL)
			{
				return false;
			}
			out.resize(ilen / 2);
			std::stringstream s1;
			int temp = 0;
			for (int i = 0; i < ilen; i += 2)
			{
				//�ַ�ת����16���ƴ����ss��
				s1 << std::hex << in[i] << in[i + 1];
				//��16�����ַ��ض���int������
				s1 >> temp;
				s1.clear();
				//�ַ�����������
				out[i / 2] = (char)temp;
			}
			return true;
		}

	};

	enum class TimeType:uint8_t {
		year,
		month,
		day,
		hour,
		min,
		sec
	};
	class CDataTime
	{
	public:
		// ����ʱ���ʽ���ĳ����ַ���"%Y-%m-%d %H:%M:%S";
		// ������system_clock���ƿռ�
		using system_clk = std::chrono::system_clock;
		// ������time_point����
		using _time_point = std::chrono::time_point<system_clk>;
	public:
		CDataTime() : m_begin(system_clk::now()) {}

		void reset() {
			m_begin = system_clk::now();
		}

		//std::chrono::microseconds,std::chrono::seconds
		template<class T>
		int64_t elapsed() const {
			return std::chrono::duration_cast<T>(system_clk::now() - m_begin).count();
		}

		time_t to_time() {
			return std::chrono::system_clock::to_time_t(m_begin);
		}

		// ��ʱ�����Ϣת��Ϊ�ַ����ĺ���
		static std::string to_string(const _time_point& t, const std::string& date_fmt) {
			std::string result;
			std::time_t c_time_t = system_clk::to_time_t(t);
			char mbstr[100];

			struct tm  cur;
#ifdef _WIN32
			if (localtime_s(&cur, &c_time_t) != 0)
#else
			if (localtime_r(&c_time_t, &cur) == NULL)
#endif
			{
				return "";
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), date_fmt.c_str(), &cur);
			if (size) {
				result = mbstr;
				return result;
			}
			return "";
		}

		// ��ʱ�����Ϣת��Ϊ�ַ����ĺ���
		static std::string to_string(time_t c_time_t) {
			char mbstr[100];
			struct tm  cur;
#ifdef _WIN32
			if (localtime_s(&cur, &c_time_t) != 0)
#else
			if (localtime_r(&c_time_t, &cur) == NULL)
#endif
			{
				return "";
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), "%Y-%m-%d %H:%M:%S", &cur);
			if (size) {
				std::string result = mbstr;
				return result;
			}
			return "";
		}
		

		// ���ַ���ת��Ϊtime_point�ĺ���,Ĭ��ʱ���ʽ"%Y-%m-%d %H:%M:%S"
		static _time_point from_string(const std::string &src_str) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			if (sscanf(src_str.c_str(), "%04d-%02d-%02d %02d:%02d:%02d", \
				&dt.tm_year, &dt.tm_mon, &dt.tm_mday, &dt.tm_hour, &dt.tm_min, &dt.tm_sec) != 6)
			{
				return system_clk::from_time_t(0);
			}
			dt.tm_year -= 1900;
			dt.tm_mon -= 1;
			/*!�������2038��ͻ�ʱ�����*/
			time_t c_time_t = std::mktime(&dt);
			auto time_pt = system_clk::from_time_t(c_time_t);
			return time_pt;
		}
		static time_t string_to_epoch(const std::string &src_str) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {0};
			if (sscanf(src_str.c_str(), "%04d-%02d-%02d %02d:%02d:%02d", \
				&dt.tm_year, &dt.tm_mon, &dt.tm_mday, &dt.tm_hour, &dt.tm_min, &dt.tm_sec) != 6)
			{
				_LOG(logTypeErr,"from_string sscanf failed err:%d! data:%s", errno, src_str.c_str());
				return 0;
			}
			dt.tm_year -= 1900;
			dt.tm_mon -= 1;
			time_t c_time_t = std::mktime(&dt);
			/*_LOG(logTypeCommon, "string_to_epoch time:%04d-%02d-%02d %02d:%02d:%02d epoch time:%d", \
				dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec,c_time_t);*/
			return c_time_t;
		}
		/* gcc 4.9 bug��ɲ�֧��get_time
		// ���ַ���ת��Ϊtime_point�ĺ���,Ĭ��ʱ���ʽ"%Y-%m-%d %H:%M:%S"
		static _time_point from_string(const std::string &src_str) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			ss >> std::get_time(&dt, "%Y-%m-%d %H:%M:%S");
			time_t c_time_t = std::mktime(&dt);
			auto time_pt = system_clk::from_time_t(c_time_t);
			return time_pt;
		}


		// ���ַ���ת��Ϊtime_point�ĺ���
		static _time_point from_string(const std::string &src_str, const std::string& date_fmt) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			ss >> std::get_time(&dt, date_fmt.c_str());
			time_t c_time_t = std::mktime(&dt);
			auto time_pt = system_clk::from_time_t(c_time_t);
			return time_pt;
		}*/


		/*�������գ�ʱ����ת���� epoch time(the Unix epoch is 00:00:00 UTC on 1 January 1970 (an arbitrary date);) ʱ��*/
		static time_t to_epoch_time(uint16_t year, uint16_t month, uint16_t day, uint16_t hour, uint16_t min, uint16_t sec) {
			std::tm dt = {};
#if 0
			std::stringstream ss;
			ss << _utility::CUtility::format("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec);
			_LOG(logTypeCommon, "%s,%d\n", ss.str().c_str(), ss.str().length());
			ss >> std::get_time(&dt, "%Y-%m-%d %H:%M:%S");
#else
			dt.tm_year = year - 1900;
			dt.tm_mon = month - 1;
			dt.tm_mday = day;
			dt.tm_hour = hour;
			dt.tm_min = min;
			dt.tm_sec = sec;
			/*
			if (sscanf(ss.str().c_str(), "%04d-%02d-%02d %02d:%02d:%02d", \
				&dt.tm_year, &dt.tm_mon, &dt.tm_mday, &dt.tm_hour, &dt.tm_min, &dt.tm_sec) != 6)
			{
				return 0;
			}*/
#endif
			time_t c_time_t = std::mktime(&dt);
			return c_time_t;
		}

		/*��ȡ epoch timeʱ��(the Unix epoch is 00:00:00 UTC on 1 January 1970 (an arbitrary date);) */
		static time_t CurrentTime()
		{
			return std::chrono::duration_cast<std::chrono::seconds>(system_clk::now().time_since_epoch()).count();
		}

		static bool UpdateSystemTime(time_t t)
		{
#if  defined(__linux__) || defined(__linux)
			struct timeval		time_tv;
			time_tv.tv_sec = t;
			time_tv.tv_usec = 0;
			if (settimeofday(&time_tv, NULL) != 0)
			{
				return false;
			}
#endif
			return true;
		}

		static bool CheckValidTime(time_t c_time_t)
		{
			/*debug����ʱ��ʽ����Ҫ���������ж��Դ���std::get_time doesn't stop parsing the input stream 
			as soon as a mismatch is found or stream is eof, but continues until the format string is exhausted instead.
			This provokes a dereference of the input stream iterator even when it is at the eof.
			In debug builds it raises an assert. In release builds it is silently ignored.*/
			time_t  start = string_to_epoch("2020-01-01 00:00:00");
			time_t end = string_to_epoch("2038-01-01 00:00:00");
			if (c_time_t <  start || c_time_t > end)
			{
				_LOG(logTypeErr,"CheckValidTime invalid: %s,%lld,%lld,%lld",to_string(c_time_t).c_str(), (int64_t)c_time_t, (int64_t)start, (int64_t)end);
				return false;
			}
			return true;
		}


		/*��ʱ��ת���������գ�ʱ����*/
		template<TimeType type>
		static uint32_t to_datatime(std::time_t c_time_t) 
		{
			char mbstr[5];
			struct tm  cur;
			std::string format;
#ifdef _WIN32
			localtime_s(&cur, &c_time_t);
#else
			localtime_r(&c_time_t, &cur);
#endif
			switch (type)
			{
			case TimeType::year:
				format = "%Y";
				break;
			case TimeType::month:
				format = "%m";
				break;
			case TimeType::day:
				format = "%d";
				break;
			case TimeType::hour:
				format = "%H";
				break;
			case TimeType::min:
				format = "%M";
				break;
			case TimeType::sec:
				format = "%S";
				break;
			default:
				break;
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), format.c_str(), &cur);
			if (size) {
				return std::stoi(mbstr);
			}
			return 0;
		}
	private:
		_time_point m_begin;
	};

}