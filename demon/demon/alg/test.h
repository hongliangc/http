#pragma once
#include <thread>
#include <iostream>
#include <vector>
#include <list>
#include <numeric>
#include <future>
#include <unordered_map>
#include <typeinfo>
#include <typeindex>
#include <functional>


#include <stdexcept>
#include <string>
#include "utility.h"
using namespace _utility;

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"



void test_future()
{
	//std::launch::async �첽���µ��߳���ִ��
	std::future<std::vector<int>> iotaFuture = std::async(std::launch::async,
		[startArg = 1]() {
		std::vector<int> numbers(25);
		std::iota(numbers.begin(), numbers.end(), startArg);
		std::cout << "calling from: " << std::this_thread::get_id() << " id\n";
		std::cout << numbers.data() << '\n';
		std::this_thread::sleep_for(std::chrono::seconds(2));
		return numbers;
	}
	);

	auto vec = iotaFuture.get(); // make sure we get the results...
	std::cout << vec.data() << '\n';
	std::cout << "printing in main (id " << std::this_thread::get_id() << "):\n";
	for (auto& num : vec)
		std::cout << num << ", ";
	std::cout << '\n';


	//std::launch::deferred �ӳ��ڵ�ǰ�߳���ִ��
	std::future<int> sumFuture = std::async(std::launch::deferred, [&vec]() {
		const auto sum = std::accumulate(vec.begin(), vec.end(), 0);
		std::cout << "accumulate in: " << std::this_thread::get_id() << " id\n";
		std::this_thread::sleep_for(std::chrono::seconds(2));
		return sum;
	});

	const auto sum = sumFuture.get();
	std::cout << "sum of numbers is: " << sum;
}



/*//using CRTP to provide an "interface" for a set of child templates;
and both the parent and the child are parametric in other template argument(s)
����ݹ�ģ��ģʽ (Curiously recurring template pattern)
*/
template <template <class> class DERIVED, class VALUE> 
class base1 {
public:
	void do_something(VALUE v) {
		printf("base1 do something\n");
	}
	void interface_do_something(VALUE v) {
		//����ת����ʱ��ģ�����DERIVED��Ҫexlicit��ָ����ʹ��DERIVED<VALUE>
		static_cast<DERIVED<VALUE>*>(this)->do_something(v);
	}
};

template <class VALUE>
class derived1 : public base1<derived1, VALUE> {
public:
	void do_something(VALUE v) {
		printf("derived1 do something\n");
	}
};

//derived1ʹ��ģ���ģ�������ʹ��derived1<int>
typedef base1<derived1, int> derived_t1;


template <typename DERIVED, typename VALUE> class base2 {
public:
	void do_something(VALUE v) {
		printf("base2 do something\n");
	}
	void interface_do_something(VALUE v) {
		static_cast<DERIVED*>(this)->do_something(v);
		//static_cast<DERIVED& >(*this).do_something(v);
	}
};

template <typename VALUE>
class derived2 : public base2<derived2<VALUE>, VALUE> {
public:
	void do_something(VALUE v) {
		printf("derived2 do something\n");
	}
};

typedef base2<derived2<int>, int> derived_t2;

void test_forward()
{
	derived_t1 derive1;
	derive1.interface_do_something(10);
	derived_t2 derive2;
	derive2.interface_do_something(10);
}





template<typename D>
class Base
{
	template<typename T>
	std::string _method(T t) { return "Base"; }
public:
	virtual void printf(){}
	template<typename T>
	std::string method(T t)
	{
#if 1
		//return static_cast<D&>(*this).template _method<T>(t);
		return static_cast<D*>(this)->template _method<T>(t);
#else		
		return ((D*)this)->_method<T>(t);
#endif
	}
};

class Derived : public Base<Derived>
{
	//friend class Base<Derived>;
public:
	virtual void printf() {}
	template<typename T>
	std::string _method(T t) { return "Derived"; }
public:
	//...
};

/*//Templated functions are instantiated at the POI and can't be virtual 
(what is the signature??How many vtable entries do you reserve?). 
Templated functions are a compile-time mechanism, virtual functions a runtime one.
ģ�庯������poi���ͽ��г�ʼ���ģ�����Ϊ�麯����ģ�庯������������ʱ�������ɵģ��麯����������
*/
int test_template_override()
{
	Base<Derived> *b = new Derived();
	std::cout << b->method<int>(std::move(1)) << std::endl;
	return 0;
}


template<typename T>
class myClass
{
	T dummy;
public:
	myClass() {};
	~myClass() {};
	template<typename U>
	void func(myClass<U> obj);

};

template<typename T>
template<typename U>

void myClass<T>::func(myClass<U> obj)
{
	std::cout << typeid(obj).name() << std::endl;
}
template<class T, class U>
void func2(myClass<T> k, myClass<U> v)
{
	//k.template func<U>(k); //even it does not compile
	//k.func<U>(v);
	k.func(v);
}
void test_template_construct()
{
	myClass<char> d;
	myClass<int> v;
	func2(d, v);
}

//����condition_variable ��Lost Wakeup and Spurious Wakeup

#include <condition_variable>
#include <iostream>
#include <thread>

std::mutex mutex_;
std::condition_variable condVar;


std::atomic<bool> dataReady{ false };

void waitingForWork() {
	std::cout << "Waiting " << std::endl;
	std::unique_lock<std::mutex> lck(mutex_);
	//condVar.wait(lck, [] { return dataReady.load(); });   // (1)
	//�ȼ������棬����Ϊ�����μ��˸���ʱ
	while (![] { return dataReady.load(); }())
	{
		//�������1s��ʱ���������dataReady�������������������������
		//��Ϊnotify_one���ͺ󲻻���䣬��������̲߳�����wait״̬���ͻᶪʧ���ź�
		//ͬʱdataReady�ڽ��뵽�ó��䳤��true
		std::cout << "Waiting 111" << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(1));
		std::cout << "Waiting 222" << std::endl;
		condVar.wait(lck);
	}
	std::cout << "Running " << std::endl;
}

void setDataReady() {
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	{
		//std::unique_lock<std::mutex> lck(mutex_); 
		//!!!!!!!!!!!! ���dataReady ���������棬�������condVar.wait���� !!!!!!!!!!!!!!!!!!!!!!!
		dataReady = true;
	}
	std::cout << "Data prepared" << std::endl;
	//notify_one���̰߳�ȫ�ģ����Բ���������
	condVar.notify_one();
	std::cout << "Data prepared end" << std::endl;
}

void condtion_var_test() {

	std::cout << std::endl;

	std::thread t1(waitingForWork);
	std::thread t2(setDataReady);

	t1.join();
	t2.join();

	std::cout << std::endl;

}


//������һ������Ϊĳ�����͵�ƫ�ػ�����
template<typename Test, template<typename...> class Ref>
struct is_specialization : std::false_type {};

/*ƫ�ػ����Լ���ģ������Զ��壬ʹ�õ�ʱ��ȥ�ж��Ƿ�ƥ��
	Ref��ʶΪ������ģ�壬ArgsΪģ�����������������
	Ref<Args...>��ʾΪƫ�ػ���ͨ�����͡�
	����RefΪvector��ArgsΪint����ʱRef<Args...>����
	vector<int>������ƫ�ػ�����
*/
// template<template<typename...> class Ref, typename... Args>
// struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template<template<typename> class Ref,class Args>
struct is_specialization<Ref<Args>,Ref>: std::true_type{};

void test_specializaton()
{
	typedef std::vector<int> vec;
	typedef int not_vec;
	std::cout << is_specialization<vec, std::vector>::value << is_specialization<not_vec, std::vector>::value;

	typedef std::list<int> lst;
	typedef int not_lst;
	std::cout << is_specialization<lst, std::list>::value << is_specialization<not_lst, std::list>::value;
}

#ifndef _WIN32 

/*! ����loacltime_r��������*/
void *mytest(void *arg)
{
	pthread_detach(pthread_self());

	time_t current;
	struct tm date;
	time(&current);

	while (1) {
		localtime_r(&current, &date);
		std::this_thread::sleep_for(std::chrono::seconds(2));
		printf("thread id:%d OK \n", *(int*)arg);
	}
}

int test_localtime_r()
{
	int i = 0;
	pthread_t tid[10];

	for (i = 0; i < 10; i++) {
		int *num = new int;
		*num = i;
		pthread_create(&tid[i], NULL, mytest, (void*)(num));
	}

	sleep(1);

	pthread_cancel(tid[0]);
	pthread_cancel(tid[1]);
	pthread_cancel(tid[2]);
	pthread_cancel(tid[3]);

	while (1)
		sleep(100000000);
}
#endif

template<class T>
class TSingleton_
{
private:
	static T &Create()
	{
		static T t;
		(void)instance;
		return t;
	}
public:
	static T &GetInstance()
	{
		return Create();
	}
	TSingleton_() = delete;
	TSingleton_(TSingleton_ &obj) = delete;
public:
	static T &instance;
};

template<class T> T &TSingleton_<T>::instance = TSingleton_<T>::Create();

class CArchiveA{};
/*!�������Ͱ󶨣�CArchiveA����ƫ�ػ�����԰���������ע�������T */
/*! ���ڰ������Ѳ������������ҷ���Ǳ�ڵ�����*/
struct tag_ {};

/*!����instantiate_bindƫ�ػ��ķ������ͣ���������Ѱ��instantiate_bind����������ʱ��
������ǿ��ʵ��������ṹ����ʹ��������Ч������*/
template <class Archive, class T>
struct bind_support;

/*!����ģ��ԭ��*/
template<class T>
void instantiate_bind(T*, int/*, tag_*/) {}

/*! CArchiveA��ƫ�ػ�ģ�巽��*/
template<class T>
typename bind_support<CArchiveA, T>::type 
instantiate_bind(T*, CArchiveA*/*, tag_*/);

/*! ���Ͱ�*/
template<class T>
struct init_bind;

/*ÿ�ΰ�һ������ T �ͻ���ʵ�����Ķ���bind2Archive<T> b,
���վ��ǻ���ֶ�����أ�����:
instantiate_bind(bindA*, 0)
instantiate_bind(bindB*, 0),
��������Ѱ��instantiate_bind����������ʱ�����е�һ��ƫ�ػ��ķ��������� bind_support<CArchiveA, T>::type��
bind_support����ǿ��ʵ��������ṹ�����еķ���������virtual���ܱ��Ϸ�����ʵ��������ʹ��������
*/
#define BIND2ARCHIVES(...)											\
	template<>															\
    struct init_bind<__VA_ARGS__> {										\
        static bind2Archive<__VA_ARGS__> const & b;						\
    };                                                                  \
    bind2Archive<__VA_ARGS__> const & init_bind<__VA_ARGS__>::b =		\
        TSingleton_<													\
            bind2Archive<__VA_ARGS__>									\
        >::GetInstance().bind();		





/*�ṩ����ע�᷽�������԰󶨵�CArchiveA*/
template<class T>
struct bind2Archive
{
	void bind(std::false_type) const
	{
		/*!ԭʼģ�����͵ĵ�2������ʱint�����ڵ��õ�2����Ϊ0����int���ʹ��ݣ��⽫��Զ����õ����أ�
		�������ض��ǽ���ָ��ת����Archive���ͣ������ȼ�����int*/
		/*���õ�ʱ����Ҫʵ�����Ĳ������󣬲���ֱ��ʹ��T*����nullptr��Ҫת����ʵ������*/
		instantiate_bind(static_cast<T*>(nullptr) , 0/*, tag_{}*/);
	}
	void bind(std::true_type) const {}

	bind2Archive const & bind() const
	{
		bind(std::is_abstract<T>{});
		return *this;
	}
};



/*!�洢�󶨶���*/
template<class Archive>
struct Storage
{
	typedef std::function<void()> callback;
	struct Callback {
		callback cb;
	};
	std::unordered_map<std::type_index, Callback> map;
};

template<class Archive,class T>
struct StorageBind
{
	StorageBind(){
		printf("StorageBind*********\n");
		auto & map = TSingleton_<Storage<Archive> >::GetInstance().map;
		/*! ͨ��typeid��ȡtype_info,Ȼ��type_info���Դ洢��type_index��*/
		auto key = std::type_index(typeid(T));
		if (map.find(key) != map.end())
			return;
		typename Storage<Archive>::Callback callback;
		callback.cb = []() {	printf("1111\n"); };
		map.insert({ std::move(key), std::move(callback) });
	}
};


template<class Archive, class T>
struct create_bind
{
	static void bind()	{
		TSingleton_<StorageBind<Archive, T> >::GetInstance();
	}
};

#if defined(_MSC_VER) && !defined(__clang__)
#   define DLL_EXPORT_ __declspec(dllexport)
#   define USED
#else // clang or gcc
#   define DLL_EXPORT_ __attribute__ ((visibility("default")))
#   define USED __attribute__ ((__used__))
#endif

//! When specialized, causes the compiler to instantiate its parameter
template <void(*)()>
struct instantiate_function_ {};

/*!��������Ѱ��instantiate_bind����������ʱ��������ǿ��ʵ��������ṹ*/
template<class Archive, class T>
struct bind_support
{
#if defined(_MSC_VER) && !defined(__clang__)
	/*!windows����������麯��������pre execute mainǰʵ����*/
	virtual void /*DLL_EXPORT_*/ instantiate();
#else // clang or gcc
	static void /*DLL_EXPORT_*/ instantiate();
	typedef instantiate_function_<instantiate> unused;
#endif
};

/*ʵ����ʵ��*/
template<class Archive, class T>
/*DLL_EXPORT_*/ void bind_support<Archive,T>::instantiate()
{
	create_bind<Archive, T>::bind();
}


class bindA {};
class bindB {};
BIND2ARCHIVES(bindA)
BIND2ARCHIVES(bindB)

void bindArchive()
{
	auto map = TSingleton_<Storage<CArchiveA> >::GetInstance().map;
	CHECK_EQ(2, map.size());
}