#include<iostream>
#include <stdio.h>
#include<string.h>
#include<stdlib.h>
#include <mutex>
#include <queue>
#include <vector>
#include "TQueue.h"
#include <algorithm>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <typeinfo>
#include "test.h"
#include "testQueue.h"
#include "protocol.h"
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "TBinarySerialize.h"
using namespace Serialize_;

using namespace std;

#ifdef WIN32
#include <windows.h>
#endif

#ifndef _WIN32
TEST_CASE("test localtime_r")
{
	test_localtime_r();
}
#endif

class testA
{
public:
	testA(){}
	~testA(){}
};

class testB
{
public:
	testB() {}
	~testB() {}
	template<class Archive>
	void serialize(Archive ar) {};
};

TEST_CASE("register_relationship")
{
	string str1 = "123456789";
	auto str2 = str1.substr(7);
	CHECK_EQ(str2, "89");

	CHECK_EQ(std::is_pod<base>::value, false);
	CHECK_EQ(std::is_class<base>::value, true);
	CHECK_EQ(traits::has_member_serialize<base, TBinaryArchive>::value, false);
	CHECK_EQ(traits::has_member_serialize<Hello, TBinaryArchive>::value,true);
	//r1 = std::is_base_of<BinaryData<char>, <BinaryData<char> >>::value;
	//测试BinaryData<char>是否为BinaryData 偏特化类型
	CHECK_EQ(is_specialization<BinaryData<char>, BinaryData>::value,true);


	auto & RelationMap = TSingleton<PolymorphicCasters>::GetInstance().map;
	Hello *phello = new Hello;
	phello->a = 0x12;
	phello->b = 0x1234;
	phello->c = 0x12345678;
	phello->d = 0x1234567812345678;
	base *pbaseHello = phello;
	Reissue *pReissue = new Reissue;
	base *pReissuebase = pReissue;
	base &pReissuebase1 = *pReissue;


	auto ret = std::is_polymorphic<std::remove_reference<decltype(*phello)>::type>::value;
	auto ret2 = std::is_polymorphic<std::remove_reference<decltype(phello)>::type>::value;
	printf("name:%s\n",  type_index(typeid(decltype(phello))).name());
	auto ret3 = std::is_polymorphic<std::remove_reference<decltype(pReissuebase1)>::type>::value;


	const auto derivedKey = std::type_index(typeid(decltype(*phello)));
	const auto baseKey = std::type_index(typeid(decltype(*pbaseHello)));
	if (derivedKey == baseKey)
	{
		printf("type index 11111\n");
	}
	

	const auto base13 = std::type_index(typeid(pReissuebase1));
	std::type_info const & ptrinfo = typeid(pReissuebase);
	std::type_info const & ptrinfo1 = typeid(*pReissuebase);
	const auto baseKey12 = std::type_index(ptrinfo);
	const auto baseKey112 = std::type_index(ptrinfo1);
	const auto derivedKey11 = std::type_index(typeid(decltype(*pReissue)));
	const auto baseKey11 = std::type_index(typeid(decltype(*pReissuebase)));//基类错误的转换，没有考虑rtti，最终类型是基类不是子类
	if (derivedKey11 == baseKey11)
	{
		printf("type index 22222\n");
	}

	auto baseIter = RelationMap.find(baseKey11);
	if (baseIter != RelationMap.end())
	{
		printf("find %s\n", baseKey11.name());

		auto const & derivedMap = baseIter->second;
		auto derivedIter = derivedMap.find(base13);
		if (derivedIter != derivedMap.end())
		{
			printf("find %s\n", base13.name());
			auto polycast = derivedIter->second;
			auto derivedObj = polycast->downcast(pReissuebase);
			std::stringstream stream;
			TBinaryArchive WArchive(eSerializeWrite, stream, true);
#if 0
			testA a;
			testB b;
			WArchive(a);
			WArchive(&a);
			WArchive(b);
			WArchive(&b);
#endif

			auto ret1 =  std::is_class<base>::value;
			auto ret2 = traits::has_serialize<base, TBinaryArchive>::value;
			WArchive(*pbaseHello);
			WArchive(pbaseHello, pbaseHello);


			Hello *phello_1 = new Hello;
			Hello *phello_2 = new Hello;
			base *phello_3 = new Hello;
			std::stringstream stream1;
			TBinaryArchive RArchive1(eSerializeRead, stream, true);
			RArchive1(*phello_1, phello_2, phello_3);
			CHECK_EQ(phello->d, phello_1->d);
			CHECK_EQ(phello->b, phello_2->b);
			CHECK_EQ(phello->d, dynamic_cast<Hello*>(phello_3)->d);
			//auto derived = PolymorphicCasters::upcast(pReissuebase1, baseInfo);
		}
	}
	if (derivedKey11 == baseKey12)
	{

	}
}


TEST_CASE("test_stringstream")
{
	char temp[] = {'1','2','\0','3'};
	std::stringstream stream;
	stream << temp;
	printf("test_stringstream  str:%s,%ld\n", stream.str().c_str(), stream.str().length());
	std::stringstream stream1;
	stream1.rdbuf()->sputn(temp, sizeof(temp));
	for (auto &c : stream1.str())
	{
		printf("%c", c);
	}
	printf("\n");
}

//测试条件变量虚假唤醒和唤醒丢失
TEST_CASE("Condition_var_test")
{
	//condtion_var_test();
}


static string ToHex1(const string& s, bool upper_case = true)
{
	ostringstream ret;
	ret << std::hex << std::setfill('0');
	for (unsigned char c : s)
		ret << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << int(c);

	cout << ret.str() << endl;
	return ret.str();
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
	printf("CheckVariable %ld,%ld,%ld,%ld\n", sizeof(TT), sizeof(TT1), sizeof(TT2), sizeof(TT3));
}

template<class T>
void CheckVariable1(BinaryData<T> &t)
{
	using TT = typename std::remove_pointer<T>::type;
	using TT1 = typename std::remove_pointer<typename std::remove_reference<T>::type>::type;
	using TT2 = typename std::remove_all_extents<typename std::remove_reference<T>::type>::type;
	//先去引用，然后去掉数组，最后去掉指针
	using TT3 = typename std::remove_pointer<typename std::remove_all_extents<typename std::remove_reference<T>::type>::type>::type;
	if (std::is_same<typename std::decay<T>::type, int*>::value)
	{
		printf("T is int*\n");
	}
	if (std::is_same<typename std::decay<T>::type, char*>::value)
	{
		printf("T is char*\n");
	}
	using TT4 = typename std::remove_pointer<typename std::decay<T>::type>::type;
	if (std::is_same<TT4,int>::value)
	{
		printf("T is int\n");
	}
	if (std::is_same<TT4, char>::value)
	{
		printf("T is char\n");
	}
	printf("BinaryData CheckVariable %ld,%ld,%ld,%ld,%ld\n", sizeof(TT), sizeof(TT1), sizeof(TT2), sizeof(TT3), sizeof(TT4));
}

template<class T>
void CheckVariable(T &&t)
{
	CheckVariable1(t);
}

TEST_CASE("TYPE_CHECK")
{
	int arr[10] = { 1,2,3,4,5,6,7,8,9,10 };
	int arr_[2][2] = { {1,2},{3,4}};
	CheckVariable(arr);
	char *buf = new char[20];
	CheckVariable(buf);
	auto Bd = Binary_data(buf, 20);
	CheckVariable(Bd);
	auto Bd1 = Binary_data(arr, 40);
	CheckVariable(Bd1);
	auto Bd2 = Binary_data(arr_, 16);
	CheckVariable(Bd2);
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
	//类型过滤
	ProcessImp(a, wArchive);
	int arr[2] = { 1,2 };
	ProcessImp(arr, wArchive);
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

#if 0
template<class T/*, enable_if_t<is_arithmetic<T>::value>*/>
int GetLength(T &&t)
{
	printf("%ld\n", sizeof(t));
	return sizeof(t);
}
template<class T, class ...Other>
int GetLength(T&& head, Other &&... tail)
{
	return GetLength(head) + GetLength(tail...);
}
#else
template<class T>
uint64_t GetLength(T &&t) {
	using TT = typename std::remove_pointer<typename std::remove_all_extents<typename std::remove_reference<T>::type>::type>::type;
	static_assert(!std::is_floating_point<TT>::value ||
		(std::is_floating_point<TT>::value && std::numeric_limits<TT>::is_iec559),
		"could not calculate the size of T");
	printf("element size:%ld,total size:%ld\n", sizeof(TT), sizeof(t));
	return sizeof(t);
}
template<class T>
uint64_t GetLength(BinaryData<T> &bd) {
	return bd.m_size;
}
template<class T, class ...Args>
uint64_t GetLength(T &&head, Args &&... tail) {
	return GetLength(std::forward<T>(head)) + GetLength(std::forward<Args>(tail)...);
}

#endif

template<class T>
void add(T &t){
	t = 15;
}
template<class T>
void copy(T &&t){
	add(std::forward<T&>(t));
}

class A
{
public:
	A() { val = 0; cout << "A construct called!\n" << endl; }
	~A() { cout << "A destruct called!\n" << endl; }
	void operator =(int a)	{ val = a;}
private:
	int val;
};

void assignment(uint8_t & t){
	t += 10;
}

TEST_CASE("Serialize")
{
	uint16_t len_1 = 0xffff;
	uint8_t len_2 = 0xff;
	A objectA;
	copy((uint8_t)len_1);
	copy(*(uint8_t*)&len_1);
	copy(len_2);
	copy(objectA);
	assignment(*(uint8_t*)&len_1);
	assignment(len_2);
	char a = 0x12;
	short b = 0x1234;
	int c = 0x12344321;
	long long d = 0x1234567812345678;
	int arr[10] = { 1,2,3,4,5,6,7,8,9,10 };
	int arr1[2][2] = { {5,6},{8,9} };
	std::stringstream stream;
	TBinaryArchive wArchive(eSerializeWrite, stream,Serialize_::TBinaryArchive::Options::LittleEndian());

	std::stringstream stream1;
	TBinaryArchive wArchive1(eSerializeWrite, stream1, false);
#if 1
	Hello hello;
	hello.a = a;
	hello.b = b;
	hello.c = c;
	hello.d = d;
	wArchive1(hello);
#else
	base *pBase = new Hello;//
	((Hello*)pBase)->a = a;
	((Hello*)pBase)->b = b;
	((Hello*)pBase)->c = c;
	((Hello*)pBase)->d = d;
	wArchive1(*pBase);
#endif

	wArchive(arr1, a, b, c, d,arr );

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
	printf("stream  len:%ld,str:%s\n", stream.str().length(), ToHex1(stream.str()).c_str());
	printf("stream1 len:%ld,str:%s\n", stream1.str().length(), ToHex1(stream1.str()).c_str());

	TBinaryArchive rArchive(eSerializeRead, stream, Serialize_::TBinaryArchive::Options::LittleEndian());

	TBinaryArchive rArchive1(eSerializeRead, stream1, false);
	Hello hello1;
	rArchive1(hello1);
	char aa = 0;
	short bb = 0;
	int cc = 0;
	long long dd = 0;
	int arr_[10] = { 0 };
	int arr1_[2][2] = {0};
	rArchive(arr1_, aa, bb, cc, dd, arr_);

	StrucTest struTest_;
	struTest_.a = 0;
	struTest_.b = 0;
	rArchive(struTest_);

	char *pBuf_ = new char[len];
	for (int i = 0; i < len; i++)
	{
		pBuf_[i] = 0;
	}
	//auto _BData = BinaryData<char*>(std::move(_pBuf), len);
	//auto _BData = BinaryData<char*>(std::forward<char*>(_pBuf), len);
	//auto BData_ = Binary_data(pBuf_, len);
	rArchive(Binary_data(pBuf_, len));
	auto length = GetLength(aa, bb, cc, dd, arr, arr1_);
	auto length_1 = GetLength(aa, bb, cc, dd, arr, arr1_, BData, struTest_);
	CHECK_EQ(a, aa);
	CHECK_EQ(b, bb);
	CHECK_EQ(c, cc);
	CHECK_EQ(d, dd);
	//CHECK_EQ(arr, arr_);
	//CHECK_EQ(arr1, arr1_);
	//CHECK_EQ(hello, hello1);
	//CHECK_EQ(pBuf, pBuf_);
	printf("Serialize OK\n");
}

TEST_CASE("Serialize1")
{
	char a = 0x12;
	short b = 0x1234;
	int c = 0x12344321;
	long long d = 0x1234567812345678;
	int arr[10] = { 1,2,3,4,5,6,7,8,9,10 };
	int arr1[2][2] = { { 5,6 },{ 8,9 } };

	std::stringstream stream1;
	TBinaryArchive wArchive1(eSerializeWrite, stream1, false);
	Hello hello;
	hello.a = a;
	hello.b = b;
	hello.c = c;
	hello.d = d;
	wArchive1(hello);
	Reissue reissue;
	reissue.m_iFlag = 1;
	reissue.m_iStatus = 0;
	reissue.m_iLat = 0x12345678;
	reissue.m_iLong = 0x98765432;
	char i = 0;
	for (auto &c: reissue.m_oDateTime)
	{
		c = i++;
	}
	canMessage_t e;
	e.id = 0x123;
	memcpy(e.byte_arr, "\xF3\x40\xBA\x09\x55\x00\x00\xBD", 8);
	reissue.m_vCanDate.push_back(e);
	e.id = 0x456;
	memcpy(e.byte_arr, "\xb0\x40\xBA\x09\x55\x00\x00\xB1", 8);
	reissue.m_vCanDate.push_back(e);
	wArchive1(reissue);

	printf("stream1 len:%ld,str:%s\n", stream1.str().length(), ToHex1(stream1.str()).c_str());

	TBinaryArchive rArchive1(eSerializeRead, stream1, false);
	Hello hello1;
	rArchive1(hello1);
	Reissue reissue1;
	rArchive1(reissue1);

	printf("Serialize1 OK\n");
}

TEST_CASE("FORWARD")
{
	test_template_override();
	test_forward();
	test_template_construct();
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
struct HasBarOfTypeInt<T, TypeSinkT<decltype(std::declval<T&>().*(&T::bar))>> :	std::is_same<typename std::decay<decltype(std::declval<T&>().*(&T::bar))>::type, int> {
	static void display(){	printf("HasBarOfTypeInt value:%d\n", std::is_same<typename std::decay<decltype(std::declval<T&>().*(&T::bar))>::type, int>::value);	}
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
	std::unique_ptr<char, void(*)(void*)> own(nullptr,std::free);
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
/*//Some C standard library functions are not guaranteed to be reentrant with respect to threads.
Functions such as strtok() and asctime() return a pointer to the result stored in function-allocated memory on a per-process basis.
Other functions such as rand() store state information in function-allocated memory on a per-process basis.
Multiple threads invoking the same function can cause concurrency problems, which often result in abnormal behavior and can cause more serious vulnerabilities,
such as abnormal termination, denial-of-service attack, and data integrity violations
*/
TEST_CASE("DATA_RACES")
{
	{
		cout << "************ deferred use of a variable returned by localtime can cause abnormal behavior"<< endl;
		time_t  t1 = time(nullptr);
		std::this_thread::sleep_for(std::chrono::seconds(2));
		time_t t2 = time(nullptr);
		struct tm *t1_tm = localtime(&t1);
		cout << "before t1 tm:" << asctime(t1_tm) << endl;

		//因为localtime返回的结果是存储在其申请的内存上的，多次调用localtime会导致上次存储的数据被覆盖
		struct tm* t2_tm = localtime(&t2);
		cout << "after t1 tm:" << asctime(t1_tm) << endl;
		cout << "after t2 tm:" << asctime(t2_tm) << endl;
	}

	{
		/*//Windows下，localtime此函数是线程安全的,这个函数都会为每一个线程分配一个单独的tm结构体。
			POSIX下 就不是线程安全的。这个函数内部使用了一个静态tm结构体，每个访问它的函数都会修改这个值*/
		cout << "************ Multiple threads invoking the same function can cause concurrency problems" << endl;
		time_t  t1 = time(nullptr);
		struct tm *t1_tm = localtime(&t1);
		cout << "before t1 tm:" << asctime(t1_tm) << endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
		std::thread thread_(std::bind([&t1_tm]() {
			time_t t2 = time(nullptr);
			struct tm* t2_tm = localtime(&t2);
			cout << "after t1 tm:" << asctime(t1_tm) << endl;
			cout << "after t2 tm:" << asctime(t2_tm) << endl;
		}));
		thread_.join();
		cout << "after2 t1 tm:" << asctime(t1_tm) << endl;
	}
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
	std::thread thread1(ThreadRead);
	std::thread thread2(ThreadWrite);
	thread1.join();
	thread2.join();
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
#ifdef WIN32
		localtime_s(&cur, &now);
#else
		localtime_r(&now, &cur);
#endif
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
