// GB32960.cpp : 定义控制台应用程序的入口点。
//
#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include <iostream>
#include "Protoco.h"
#include <list>
#include <string>
#include <map>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
using namespace std;
#ifdef GB32960
#if 1
//char buf[65535] = "232302FE4C44503331423936314A4736373133333701014D120B150A002101010301000000012EB60E8B271047010F07D0000002010103374E204E20360E602710050006CCB20701D09BF906013F0F2C011F0F14010233010233070000000000000000000801010E8B271000600001600F290F290F280F1D0F280F280F280F240F2B0F250F2A0F290F270F280F290F280F1A0F250F290F260F280F290F280F270F280F250F280F270F290F190F140F280F240F270F250F280F250F260F270F290F1F0F2A0F260F290F260F290F250F290F270F280F1F0F230F280F270F240F270F270F250F270F280F260F2B0F2C0F2B0F280F290F290F2A0F240F260F280F270F2A0F280F280F2B0F260F280F260F270F2A0F250F280F2B0F280F280F280F250F280F290F290F270F250F280F250F2A0901010030FF3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333CF";
char buf[65535] = "232302fe4c474a453133454133484d36313338313801014d15051b1108340101030100ea0020236d0d892a3a29012e07d0380002010101555550530c850d7029d4050006cfc8c301d3503506010d0e1f01590e04010146010743070000000000000000000801010d892a3a00600001600e1e0e1b0e1c0e1d0e0e0e1d0e1c0e1e0e060e1c0e1b0e1d0e1f0e1c0e1e0e1f0e0e0e1c0e1c0e1d0e140e1c0e1b0e1e0e1d0e1e0e1b0e1d0e140e1b0e1c0e1c0e0c0e1d0e1b0e1d0e1c0e1c0e1c0e1c0e080e1b0e1b0e1b0e0e0e1b0e1a0e1c0e1b0e1a0e1b0e1b0e0a0e1b0e1b0e1c0e060e1b0e1a0e1d0e1c0e1a0e1b0e1c0e0a0e1b0e1b0e1c0e130e1d0e1c0e1c0e1d0e1c0e1c0e1d0e120e1c0e1b0e1c0e0c0e1c0e1c0e1d0e1e0e1d0e1c0e1d0e040e1c0e1c0e1e0e0d0e1c0e1c0e1d0901010030464545454444434344444444454544444444444444444444444444444444444444444545454444444444444446464646c3";

class A {
public:

	A()
	{
		printf("address:%08x, default constructor called, m_a:%d\n", this, m_a);
	}
	A(int val) :m_a(val) { printf("address:%08x, constructor called, m_a:%d\n", this, m_a); }
	A(const A &a)
	{
		printf("address:%08x,copy constructor called, m_a:%d\n", this, m_a);
		m_a = a.m_a;
	}
	A &operator =(const A &a)
	{
		printf("address:%08x,operator =  called, m_a:%d\n", this, m_a);
		m_a = a.m_a;
	}
	~A()
	{
		printf("address:%08x,destructor  called, m_a:%d\n", this, m_a);
	}
public:
	int m_a;
};


int main()
{
	{

		char head[32] = { '\0' };
		float flat, flog = 0.0;
		char lat[32] = { '\0' };
		char log[32] = { '\0' };
		char date[32] = { '\0' };
		char time[32] = { '\0' };
		//char regex[] = "+CGPSINFO: 3027.504477,N,11424.265605,E,120121,005835.0,2.8,0.0,358.2";
		char regex[] = "+CGPSINFO: 3027.504477,N,11424.265605,E,,,2.8,0.0,358.2";
		//char regex[] = "+CGPSINFO: ,,,,,,,,";
		//"%32[^:]:%32[^,]%*[^,],%32[^,]%*[^,],%32[^,]%32[^,]"
		int rett = sscanf(regex, "%32[^:]:%32[^,],%*[^,],%32[^,],%*[^,],%32[^,],%32[^,],", head, lat, log, date, time);
		flat = std::stof(lat);
		flog = std::stof(log);
		char regex1[] = "+ICCID: 89860117750025026528";
		char iccid[32] = { '\0' };
		rett = sscanf(regex1, "%*[^0-9]%32[0-9]", iccid);
		printf("+ICCID iccid:%s\r\n", iccid);

		char regex2[] = "+CFUN: 4294967295";
		unsigned int status = 0;
		rett = sscanf(regex1, "%*[^0-9]%d", &status);
		printf("+CFUN status:%d\r\n", status);

		int type = -1;
		char regex3[] = "460010055787572";
		rett = sscanf(regex3, "460%2d", &type);
		printf("+CFUN status:%d\r\n", type);

		int freq = -1;
		char regex4[] = "+CGPSINFO: 1";
		rett = sscanf(regex4, "%*[^0-9]%d[0-9]", &freq);
		printf("+CFUN freq:%d\r\n", freq);

		std::string data = "+CGPSINFOCFG: 10,31,0";
		{
			/* response example:+CGPSINFO: (0-255),(0-262143)*/
			char str[32];
			int time = -1, config = -1;
			rett = sscanf(data.c_str(), "%*[^0-9]%d,%d", &time, &config);

			printf("Process CGPSINFOCFG time:%d, config:%d\r\n", time, config);
		}

		{
			string data = "$GPGSA,A,2,03,16,22,27,29,31,32,,,,,,1.2,0.8,0.8*39";
			std::string delim = ",";
			auto index = 0U;
			auto start = 0U;
			auto end = data.find(delim);
			while (end != std::string::npos)
			{
				if (data.substr(start, end - start).length() == 0) {
					break;
				}
				printf("index:%d,%s\n", index,data.substr(start, end - start).c_str());
				start = end + delim.length();
				end = data.find(delim, start);
				index++;
			}
			printf("$GPGSA index:%d\r\n", index);

		}
	}

	char response[1024] = { 0xd,0xa,0x0,0x2b,0x43,0x47,0x50,0x53,0x49,0x4e,0x46,0x4f,0x3a,0x20,0x33,0x30,0x32,0x37,0x2e,0x35,0x31,0x30,0x33,0x37,0x32,0x2c,0x4e,0x2c,0x31,0x31,0x34,0x32,0x34,0x2e,0x32,0x36,0x33,0x39,0x33,0x38,0x2c,0x45,0x2c,0x31,0x31,0x30,0x31,0x32,0x31,0x2c,0x30,0x39,0x30,0x32,0x34,0x31,0x2e,0x30,0x2c,0x33,0x38,0x2e,0x31,0x2c,0x30,0x2e,0x30,0x2c,0x31,0x36,0x31,0x2e,0x39,0xd,0xa };
	std::string data;
	data.assign(response, 75);
	int l1en = data.length();
	int found = data.find("+CGPSINFO:",0);
	char *p = new char[1];
	memset(p, 0, 1);
	delete[] p;
	unsigned short temp = 0x8001;
	short id = temp & 0x7fff;
	/*获取第15位的更新标志*/
	short flag = temp & 0x8000;
	// 	vector<A> a;
	// 	a.resize(10);
	// 	a.push_back(A(1));
	// 	printf("*********************************\n");
	// 	a.push_back(A(2));
	// 	printf("*********************************\n");
	// 	a.emplace_back(A(3));
	// 	printf("*********************************\n");
	{
		std::vector<A> a;
		std::cout << "call emplace_back:\n";
		a.emplace_back(0);
	}
	{
		std::vector<A> a;
		std::cout << "call push_back:\n";
		a.push_back(1);
	}

	int len = strlen(buf);
	if (len % 2 != 0)
	{
		cout << "buf len is not even number!" << endl;
		return 1;
	}

	char *pData = new char[len / 2];
	const char *s = buf;
	for (int i = 0; i < len / 2; i++)
	{
		unsigned int val = 0;
		if (sscanf_s(s, "%02x", &val) != 1)
		{
			return 1;
		}
		s += 2;
		pData[i] = val;
	}
	CGBT32960PX37 x37;
	x37.Initialize();
	//去掉一个校验位,上报数据是大端数据，解析后需要转换成小端
	int ret = x37.UnSerialize((BYTE*)pData, len / 2 - 1);
	if (ret == RET_FAIL)
	{
		cout << "parse failed!" << endl;
	}

	string out;
	CUtility::ConvertStr2Hex((unsigned char*)pData, len / 2, out);
	ret = memcmp(out.c_str(), buf, len);
	out.clear();
	CUtility::ConvertHex2Str((unsigned char*)buf, len, out);
	int olen = out.length();
	ret = memcmp(out.c_str(), pData, olen);

	system("pause");
	return 0;
}
#else
#include <functional>
#include <iostream>
#include <memory>
#include <array>
#include <regex>
#include "feature.h"
#include "md5.h"
using namespace std;


int main()
{

	//测试md5文件校验耗时
	auto begin = std::chrono::high_resolution_clock::now();
	KMD5 md5;
	unsigned char byFileHash16[16] = { 0 };
	char bySWFileHash32[33] = { 0 };
	memset(byFileHash16, 0, 16);
	memset(bySWFileHash32, 0, 33);
	md5.MD5HashFile("D:\\一汽\\升级\\1.pak", byFileHash16);
	md5.Byte16ToChar32(byFileHash16, bySWFileHash32);
	auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - begin);
	printf("************* Time spent in md5 is : %lld\n", interval.count());

	system("pause");
	return 0;
}

#endif



#endif
