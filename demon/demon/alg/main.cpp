#include<iostream>
#include <stdio.h>
#include<string.h>
#include<stdlib.h>
#include <mutex>
#include <queue>
#include <vector>
#include "TQueue.h"
#include <algorithm>
#include <windows.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "test.h"
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "TBinarySerialize.h"
using namespace Serialize_;

using namespace std;

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
		unsigned short lelf = min(len, m_size - m_out &(m_size - 1));
		memcpy(buf, m_buf + (m_out & (m_size - 1)), lelf);
		memcpy(buf + lelf, m_buf, len - lelf);
		m_out += len;
		return len;
	}
	unsigned short Write(char *buf, unsigned short len)
	{
		//获取使用空间大小    
		unsigned short used_size = GetUsedlen();
		len = min(len, m_size - used_size);
		unsigned short lelf = min(len, m_size - (m_in &(m_size - 1)));
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

CCircleBuf gCircleBuf;
DWORD WINAPI ThreadRead(LPVOID lparam)
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
	return 0;
}


DWORD WINAPI ThreadWrite(LPVOID lparam)
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
	return 0;
}



// template<class T>
// inline typename enable_if_t<std::is_array<T>::value> 
// CheckVariable1(T &t)
// {
// 	using TT = typename std::remove_pointer<T>::type;
// 	using TT1 = typename std::remove_pointer<typename std::remove_reference<T>::type>::type;
// 	using TT2 = typename std::remove_all_extents<typename std::remove_reference<T>::type>::type;
// 	using TT3 = typename std::remove_reference<typename std::remove_all_extents<T>::type>::type;
// 	printf("array CheckVariable %d,%d,%d,%d\n",sizeof(TT), sizeof(TT1), sizeof(TT2), sizeof(TT3));
// }

template<class T>
void CheckVariable1(T &t)
{
	using TT = typename std::remove_pointer<T>::type;
	using TT1 = typename std::remove_pointer<typename std::remove_reference<T>::type>::type;
	using TT2 = typename std::remove_all_extents<typename std::remove_reference<T>::type>::type;
	using TT3 = typename std::remove_pointer<typename std::remove_reference<typename std::remove_all_extents<T>::type>::type>::type;
	//using TT4 = decltype(T);
	printf("CheckVariable %d,%d,%d,%d\n", sizeof(TT), sizeof(TT1), sizeof(TT2), sizeof(TT3));
}

template<class T>
void CheckVariable1(BinaryData<T> &t)
{
	using TT = typename std::remove_pointer<T>::type;
	using TT1 = typename std::remove_pointer<typename std::remove_reference<T>::type>::type;
	using TT2 = typename std::remove_all_extents<typename std::remove_reference<T>::type>::type;
	using TT3 = typename std::remove_pointer<typename std::remove_reference<typename std::remove_all_extents<T>::type>::type>::type;
	if (std::is_same<std::decay<T>::type, int*>::value)
	{
		printf("T is int*\n");
	}
	if (std::is_same<std::decay<T>::type, char*>::value)
	{
		printf("T is char*\n");
	}
	using TT4 = std::remove_pointer<typename std::decay<T>::type>::type;
	if (std::is_same<TT4,int>::value)
	{
		printf("T is int\n");
	}
	if (std::is_same<TT4, char>::value)
	{
		printf("T is char\n");
	}
	printf("BinaryData CheckVariable %d,%d,%d,%d,%d\n", sizeof(TT), sizeof(TT1), sizeof(TT2), sizeof(TT3), sizeof(TT4));
}

template<class T>
void CheckVariable(T &&t)
{
	CheckVariable1(t);
}

TEST_CASE("TYPE_CHECK")
{
	int arr[10] = { 1,2,3,4,5,6,7,8,9,10 };
	CheckVariable(arr);
	char *buf = new char[20];
	CheckVariable(buf);
	auto Bd = Binary_data(buf, 20);
	CheckVariable(Bd);
	auto Bd1 = Binary_data(arr, 40);
	CheckVariable(Bd1);
	printf("TYPE_CHECK finish!\n");
}

using yes1 = std::true_type;
using no1 = std::false_type;

struct test0
{
	void hello() {};
};
struct test1
{
};
template <class T>
struct has_non_serialize_imp{
	template<class TT>
	/*!It's an comma-separated list of expressions, the type is identical to the type of 
	the last expression in the list. It's usually used to verify that the first expression
	is valid (compilable, think SFINAE), the second is used to specify that decltype should
	return in case the first expression is valid*/
	static auto fun(int)->decltype(declval<TT&>().hello(), yes1()) {};
	template<class TT>
	static no1 fun(...) {};
	static const bool value = std::is_same<decltype(fun<T>(0)), yes1>::value;
};

template <class T>
struct Check : std::integral_constant<bool, has_non_serialize_imp<T>::value>{};




template<class T,class A>
struct has_non_save_imp
{
	template<class TT,class AA>
	static auto test(int)->decltype(save(declval<AA&>(), declval<TT const&>()), yes1());
	template<class TT,class AA>
	static no1 test(...);
	static const bool value = std::is_same<decltype(test<T, A>(0)), yes1>::value;

	template<class TT, class AA>
	static auto test2(int)->decltype(save(declval<AA&>(), declval<typename std::remove_const<TT>::type&>()), yes1());
	template<class TT, class AA>
	static no1 test2(...);
	static const bool not_const_type = std::is_same<decltype(test2<T, A>(0)), yes1>::value;
};

template <class T, class ArchiveType, std::enable_if_t<std::is_integral<T>::value>* = nullptr> inline
void ProcessImp(T const &t, ArchiveType &a)
{
	printf("111111\n");
}

template <class T, class ArchiveType, std::enable_if_t<std::is_array<T>::value>* = nullptr> inline
void ProcessImp(T &t, ArchiveType &a)
{
	printf("22222\n");
}


typedef struct tagStrucTest
{
	int a;
	int b;
	tagStrucTest()
	{
		a = 0x1234;
		b = 0x5678;
	}
private:
	friend class traits::access;
	template<class ArchiveType>
	void serialize(ArchiveType &ar)
	{
		ar(a, b);
	}
}StrucTest;

typedef struct tagStrucTest1
{
	int a;
	int b;
	tagStrucTest1()
	{
		a = 0x1234;
		b = 0x5678;
	}
	template<class ArchiveType>
	void serialize(ArchiveType &ar)
	{
		ar(a, b);
	}
}StrucTest1;

template<typename, typename T>
struct has_serialize1 {
	static_assert(
		std::integral_constant<T, false>::value,
		"Second template parameter needs to be of function type.");
};

template<typename C, typename Ret, typename... Args>
struct has_serialize1<C, Ret(Args...)> {
private:
	template<typename T>
	static constexpr auto check(T*)-> typename	std::is_same<decltype(std::declval<T>().serialize(std::declval<Args>()...)),Ret>::type;  // attempt to call it and see if the return type is correct

	template<typename>
	static constexpr std::false_type check(...);

	typedef decltype(check<C>(0)) type;

public:
	static constexpr bool value = type::value;
};

TEST_CASE("TRAITS")
{
	uint8_t a = 1;
	using T = decltype(a);

	std::stringstream stream;
	TBinaryArchive wArchive(eSerializeWrite, stream, Serialize_::TBinaryArchive::Options::BigEndian());
	using ArchiveType = decltype(wArchive);
	//是否支持数组序列化和pod类型序列化
	bool ret1 = traits::has_serialize<T, TBinaryArchive>::value;
	bool ret2 = traits::has_serialize_array<T, TBinaryArchive>::value;
	//ProcessImp(a, wArchive);
	int arr[2] = { 1,2 };
	//ProcessImp(arr, wArchive);
	using T1 = decltype(arr);
	bool ret9 = is_array<T1>::value;
	bool ret7 = traits::has_serialize<T1, TBinaryArchive>::value;
	bool ret8 = traits::has_serialize_array<T1, TBinaryArchive>::value;

	//检测是否有save方法
	bool ret3 = has_non_save_imp<T, TBinaryArchive>::value;
	//检测是否有hello方法
	bool ret4 = has_non_serialize_imp<T>::value;
	bool ret5 = has_non_serialize_imp<test0>::value;
	bool ret6 = has_non_serialize_imp<test1>::value;

	//是否支持类成员函数序列化
	StrucTest struTest;
	bool ret10 = traits::has_member_serialize<TBinaryArchive, StrucTest>::value;
	bool ret11 = traits::has_member_serialize<TBinaryArchive, StrucTest1>::value;
	traits::access::member_serialize(wArchive, struTest);

	//检测是否有成员函数
	auto ret12 = has_serialize1<StrucTest, void(TBinaryArchive)>::value;
	auto ret13 = has_serialize1<StrucTest1, void(TBinaryArchive)>::value;
	//static_assert(std::is_same<decltype(test<test0>::fun(), 3.1), double>::value, "Will not fire");
	printf("1111111\n");

}


TEST_CASE("Serialize")
{
	std::string;
	char a = 0x12;
	short b = 0x1234;
	int c = 0x12344321;
	long long d = 0x1234567812345678;
	int arr[10] = { 1,2,3,4,5,6,7,8,9,10 };
	std::stringstream stream;
	TBinaryArchive wArchive(eSerializeWrite, stream,Serialize_::TBinaryArchive::Options::BigEndian());
	wArchive(a, b, c, d,arr);

	StrucTest struTest;
	struTest.a = 0x123456;
	struTest.b = 0x654321;
	wArchive(struTest);

	int len = 20;
	char *pBuf = new char[len];
	for (int i = 0 ;i < len; i++)
	{
		pBuf[i] = i;
	}
	//auto BData1 = BinaryData<char*>(std::forward<char*>(pBuf), len);
	auto BData = Binary_data(pBuf, len); //if T is lvalue that will be deduced to T&
	//auto BData = Binary_data_(pBuf, len);
	wArchive(BData);
	printf("len:%d,str:%s\n", stream.str().length(), stream.str().c_str());

	TBinaryArchive rArchive(eSerializeRead, stream, Serialize_::TBinaryArchive::Options::BigEndian());
	char aa = 0;
	short bb = 0;
	int cc = 0;
	long long dd = 0;
	int arr_[10] = { 0 };
	rArchive(aa, bb, cc, dd, arr_);

	StrucTest struTest_;
	struTest_.a = 0;
	struTest_.b = 0;
	rArchive(struTest_);

	char *_pBuf = new char[len];
	for (int i = 0; i < len; i++)
	{
		_pBuf[i] = 0;
	}
	//auto _BData = BinaryData<char*>(std::move(_pBuf), len);
	//auto _BData = BinaryData<char*>(std::forward<char*>(_pBuf), len);
	auto _BData = Binary_data(_pBuf, len);
	rArchive(_BData);


	printf("Serialize OK\n");
}


//this goes in some header so you can use it everywhere
template<typename T>
struct TypeSink {
	using Type = void;
};
template<typename T>
using TypeSinkT = typename TypeSink<T>::Type;

//use case
template<typename T, typename = void>
struct HasBarOfTypeInt : std::false_type {
	static void display()	{	printf("HasBarOfTypeInt false\n");}
};

template<typename T>
struct HasBarOfTypeInt<T, TypeSinkT<decltype(std::declval<T&>().*(&T::bar))>> :
	std::is_same<typename std::decay<decltype(std::declval<T&>().*(&T::bar))>::type, int> {
	static void display(){	printf("HasBarOfTypeInt value:%d\n",value);	}
};

struct S {	int bar;};
struct S1 {	char bar;};
struct K {};

template<typename T, typename = TypeSinkT<decltype(&T::bar)>>
void print(T) {
	std::cout << "has bar" << std::endl;
}
void print(...) {
	std::cout << "no bar" << std::endl;
}
TEST_CASE("SFINAE_CHECK")
{
	HasBarOfTypeInt<S>::display();
	HasBarOfTypeInt<S1>::display();
	HasBarOfTypeInt<K>::display();
	std::cout << "bar is int: " << HasBarOfTypeInt<S>::value << std::endl;
	std::cout << "bar is int: " << HasBarOfTypeInt<S1>::value << std::endl;
	std::cout << "bar is int: " << HasBarOfTypeInt<K>::value << std::endl;
	print(S{});
	print(S1{});
	print(K{});
	printf("SFINAE_CHECK OK\n");
}


TEST_CASE("future")
{
	test_future();
}

template <typename T>
std::string
type_name()
{
	typedef typename std::remove_reference<T>::type TR;
	std::unique_ptr<char, void(*)(void*)> own
	(
#ifndef _MSC_VER
		abi::__cxa_demangle(typeid(TR).name(), nullptr,
			nullptr, nullptr),
#else
		nullptr,
#endif
		std::free
	);
	std::string r = own != nullptr ? own.get() : typeid(TR).name();
	if (std::is_const<TR>::value)
		r += " const";
	if (std::is_volatile<TR>::value)
		r += " volatile";
	if (std::is_lvalue_reference<T>::value)
		r += "&";
	else if (std::is_rvalue_reference<T>::value)
		r += "&&";
	return r;
}


// overloads

/* 测试std::move(将左值转化为右值) 和std::forwad */
void overloaded(int &arg) { std::cout << "by lvalue\n"; }
void overloaded(int const &arg) { std::cout << "by const lvalue\n"; }
void overloaded(int && arg) { std::cout << "by rvalue\n"; }

template< typename t >
/* "t &&" with "t" being template param is special, and  adjusts "t" to be
(for example) "int &" or non-ref "int" so std::forward knows what to do. */
void forwarding(t && arg) {
	type_name<decltype(declval<t>())>();
	std::cout << "via std::forward: ";
	//转发需要在模板T&& 下使用，否则返回值是rvalue
	overloaded(std::forward< t >(arg));
	std::cout << "via std::move: ";
	overloaded(std::move(arg)); // conceptually this would invalidate arg
	std::cout << "by simple passing: ";
	overloaded(arg);
}

void _test_forward() {
	std::cout << "111111111 passes rvalue:\n";
	forwarding(5);
	std::cout << "222222222 passes lvalue:\n";
	int x = 5;
	forwarding(x);

	std::cout << "333333333 wrong usage of std::forward\n";
	/*错误使用不能完美转发，此时只是转换成rvalue，不能完美转发
	正确的使用方式应该是如下
	template<T>
	void foo(T &&t)
	{
		std::forward<T>(t);
	}
	*/
	overloaded(std::forward<int>(5));
	overloaded(std::forward<int>(x));
}

TEST_CASE("Reference_collapsing")
{
	int i;
	auto ret0 = std::is_same< int &, decltype(i) >::value;
	//reference 
	auto ret1 = std::is_same< int &, decltype((i)) >::value;
	//xvalue
	auto ret2 = std::is_same< int &&, decltype(std::move(i))>::value;
	//if T is prvalue, decltype return T
	auto ret3 = std::is_same< int &&, decltype(5)>::value;
	overloaded(i);
	overloaded(std::forward<int>(i));
	overloaded(std::forward<int>(5));
	overloaded(5);
	_test_forward();

	/*declval add_rvalue_reference(返回右值引用)
		T   -> T&&
		T&	-> T& &&, T&
		T&& -> T&& &&,T&& 
	*/
	auto ret4 = std::is_same< int &&, decltype(std::declval<int>())>::value;
	auto ret5 = std::is_same< int &, decltype(std::declval<int&>())>::value;
	auto ret6 = std::is_same< int &&, decltype(std::declval<int&&>())>::value;

	std::cout << type_name<decltype(std::declval<int>())>() << '\n';
	std::cout << type_name<decltype(std::declval<int&>())>() << '\n';
	std::cout << type_name<decltype(std::declval<int&&>())>() << '\n';
	printf("Reference_collapsing OK\n");
}

#if 0
TEST_CASE("TEST 1")
{
	gCircleBuf.Initial(1024);
	char *temp = new char[128];
	unsigned short tt = 65535 * 2;
	unsigned short t1 = 65527;
	unsigned short t2 = 915;
	unsigned short t3 = 11;
	unsigned short t = min(t3, (t2 - t1));
	unsigned short offset = t2 - t1;
	HANDLE hTread1 = ::CreateThread(NULL, 0, ThreadRead, NULL, 0, NULL);
	HANDLE hTread2 = ::CreateThread(NULL, 0, ThreadWrite, NULL, 0, NULL);
	WaitForSingleObject(hTread1, INFINITE);
	WaitForSingleObject(hTread2, INFINITE);
	CloseHandle(hTread1);
	CloseHandle(hTread2);
}

//3*24*60*60/10
#define COUNT 25920
TEST_CASE("TQUEUE_TEST")
{

	std::mutex	m_mutex;
	std::condition_variable m_cond;
	srand(time(NULL));
	time_t cur = time(NULL);
	auto fn_time = [](unsigned int t)->string {
		char buff[128] = { '\0' };
		time_t now = t;
		struct tm  cur;
		localtime_s(&cur, &now);
		sprintf_s(buff, sizeof(buff), "%04d-%02d-%02d %02d:%02d:%02d", cur.tm_year + 1900, cur.tm_mon + 1, cur.tm_mday, cur.tm_hour, cur.tm_min, cur.tm_sec);
		return buff;
	};
	TQueue<CanData> CanQueue;
	CanQueue.Initial(COUNT);
	CanQueue.LoadFile("raw.txt");
	//CanQueue.Initial(10);
	auto fn_write = [cur,fn_time](TQueue<CanData> &CanQueue) {
		printf("fn_write CanQueue address:0x%08x \n", &CanQueue);
		unsigned int index = 0;
		do
		{
			CanData data;
			data.m_mileage = index;
			data.m_speed = index;
			data.m_time = (unsigned int)cur + index * 10;
			CanQueue.WriteData(data);
			index++;
// 			if (index++ % 1000 == 0)
// 			{
// 				//printf("write data index:%d, mileage:%d, speed:%d, time:%s \n", index % COUNT, data.m_mileage, data.m_speed, fn_time(data.m_time).c_str());
// 				if (CanQueue.IsFull())
// 				{
// 					auto t1 = std::chrono::high_resolution_clock::now();
// 					CanQueue.SaveFile("raw.txt");
// 					auto t2 = std::chrono::high_resolution_clock::now();
// 					//printf("it cost:%lldms to save data!\n", std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1));
// 					break;
// 				}
// 			}
			//assert(index % COUNT == CanQueue.m_tail);
			std::this_thread::sleep_for(chrono::microseconds(1000));
		} while (1);
	};
	std::thread QueueWrite(fn_write, std::ref(CanQueue));


	auto fn_read = [fn_time](TQueue<CanData> *CanQueue) {
		printf("fn_read CanQueue address:0x%08x \n", CanQueue);
		int count = 1;
		CanData data;
		CanData canData;
		unsigned int cur = CanQueue->head()->m_time;
		do
		{
			//const CanData *pData = (*CanQueue)[9];
			//CanQueue->ReadData(data);
			//int result = memcmp(pData, &data, sizeof(pData));
			//printf("read data ,result:%d,count:%d, mileage:%d, speed:%d, time:%d \n", result,CanQueue->GetQueueUsedSize(), data.m_mileage, data.m_speed, data.m_time);
// 			if (CanQueue->IsFull())
// 			{
// 				auto t1 = std::chrono::high_resolution_clock::now();
// 				CanQueue->LoadFile("raw.txt");
// 				auto t2 = std::chrono::high_resolution_clock::now();
// 				printf("it cost:%lldms to load data!\n", std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1));
// 			}
			{
				//二分法进行数据查找
				auto t1 = std::chrono::high_resolution_clock::now();
				int r = 1;// rand() % 10;
				canData.m_time = r + (unsigned int)cur + 10 * count;
				if (++count %10 == 0)
				{
					count += 10*10;
				}
				//自定义数据比较方法
				struct compare<CanData> cmp(canData);
				cmp.m_fn = [fn_time](const CanData &first, const CanData &second)->int {
					if (first.m_time + 10 > second.m_time && first.m_time <= second.m_time) {
						string start = fn_time(first.m_time);
						string end = fn_time(first.m_time + 10);
						string tt = fn_time(second.m_time);
						printf("find date:%s, in range(%s,%s)\n", tt.c_str(), start.c_str(), end.c_str());
						return 0;
					}
					else if (first.m_time + 10 <= second.m_time) {
						return 1;
					}
					else if (first.m_time > second.m_time) {
						return -1;
					}
				};

				unsigned int iStart =  CanQueue->head()->m_time;
				unsigned int iEnd = CanQueue->tail()->m_time;
				string start = fn_time(iStart);
				string end = fn_time(iEnd);
				string tt = fn_time(canData.m_time);
				printf("search time:%s range(%s,%s)\n", tt.c_str(), start.c_str(), end.c_str());
				if (canData.m_time +10 < CanQueue->head()->m_time)
				//if (canData.m_time < CanQueue->head()->m_time)
				{
					printf("can't find,search time is less than begin time!\n");
					continue;
				}
				if (canData.m_time > CanQueue->tail()->m_time)
				{
					printf("can't find,search time is more than end time!\n");
					std::this_thread::sleep_for(std::chrono::seconds(5));
					continue;
				}
				//查找
				int index = CanQueue->BinarySearch(cmp);
				if (index != -1)
				{
					for (int i = 0; i <= index; i++)
					{
						string tt = fn_time((*CanQueue)[i]->m_time);
						printf("1111 index:%d time:%s\n", i, tt.c_str());
					}
					CanQueue->Pop(index + 1);
				}
				else
				{
					index = CanQueue->Search(cmp);
					if (index != -1)
					{
						for (int i = 0; i <= index; i++)
						{
							string tt = fn_time((*CanQueue)[i]->m_time);
							printf("222 index:%d time:%s\n", i, tt.c_str());
						}
						CanQueue->Pop(index + 1);
					}
					else
					{
						printf("can't find data!\n");
					}
				}
				auto t2 = std::chrono::high_resolution_clock::now();
				printf("it cost :%lldms to read data!\n", std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1));
			}
			std::this_thread::sleep_for(chrono::microseconds(900));
			//break;
		} while (1);
	};
	std::thread QueueRead(fn_read, &CanQueue);
	QueueRead.join();
	QueueWrite.join();
}

#endif
