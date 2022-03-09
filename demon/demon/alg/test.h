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
	//std::launch::async 异步在新的线程中执行
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


	//std::launch::deferred 延迟在当前线程中执行
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
奇异递归模板模式 (Curiously recurring template pattern)
*/
template <template <class> class DERIVED, class VALUE> 
class base1 {
public:
	void do_something(VALUE v) {
		printf("base1 do something\n");
	}
	void interface_do_something(VALUE v) {
		//类型转换的时候模板参数DERIVED需要exlicit的指定，使用DERIVED<VALUE>
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

//derived1使用模板的模板避免了使用derived1<int>
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
模板函数是以poi类型进行初始化的，不能为虚函数，模板函数是依靠编译时机制生成的，虚函数是运行期
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

//测试condition_variable 的Lost Wakeup and Spurious Wakeup

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
	//等价于下面，但是为了掩饰加了个延时
	while (![] { return dataReady.load(); }())
	{
		//特意添加1s延时，测试如果dataReady不加锁保护，可以造成死锁，
		//因为notify_one发送后不会记忆，如果接受线程不处于wait状态，就会丢失该信号
		//同时dataReady在进入到该出变长了true
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
		//!!!!!!!!!!!! 如果dataReady 不在锁下面，可能造成condVar.wait死锁 !!!!!!!!!!!!!!!!!!!!!!!
		dataReady = true;
	}
	std::cout << "Data prepared" << std::endl;
	//notify_one是线程安全的，可以不用锁保护
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


//测试是一个类型为某种类型的偏特化类型
template<typename Test, template<typename...> class Ref>
struct is_specialization : std::false_type {};

/*偏特化，自己的模板参数自定义，使用的时候去判断是否匹配
	Ref标识为基础的模板，Args为模板参数，在特例化中
	Ref<Args...>表示为偏特化的通用类型。
	例如Ref为vector，Args为int，此时Ref<Args...>就是
	vector<int>，满足偏特化条件
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

/*! 测试loacltime_r导致死锁*/
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
		sleep(5);
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
/*!测试类型绑定，CArchiveA类型偏特化后可以绑定任意其它注册的类型T */
/*! 用于帮助摆脱参数依赖，查找发现潜在的重载*/
struct tag_ {};

/*!用做instantiate_bind偏特化的返回类型，当编译器寻在instantiate_bind的重载类型时，
它将被强制实例化这个结构，即使它不是有效的重载*/
template <class Archive, class T>
struct bind_support;

/*!函数模板原型*/
template<class T>
void instantiate_bind(T*, int/*, tag_*/) {}

/*! CArchiveA的偏特化模板方法*/
template<class T>
typename bind_support<CArchiveA, T>::type 
instantiate_bind(T*, CArchiveA*/*, tag_*/);

/*! 类型绑定*/
template<class T>
struct init_bind;

/*每次绑定一个类型 T 就会多个实例化的对象bind2Archive<T> b,
最终就是会出现多的重载，比如:
instantiate_bind(bindA*, 0)
instantiate_bind(bindB*, 0),
当编译器寻在instantiate_bind的重载类型时，其中的一个偏特化的返回类型是 bind_support<CArchiveA, T>::type，
bind_support将被强制实例化这个结构，其中的方法必须是virtual才能保障方法被实例化，即使不被调用
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





/*提供类型注册方法，可以绑定到CArchiveA*/
template<class T>
struct bind2Archive
{
	void bind(std::false_type) const
	{
		/*!原始模板类型的第2个参数时int，现在调用第2参数为0总是int类型传递，这将永远是最好的重载，
		其他重载都是接受指针转换到Archive类型，其优先级低于int*/
		/*调用的时候需要实例化的参数对象，不能直接使用T*，用nullptr需要转换成实例对象*/
		instantiate_bind(static_cast<T*>(nullptr) , 0/*, tag_{}*/);
	}
	void bind(std::true_type) const {}

	bind2Archive const & bind() const
	{
		bind(std::is_abstract<T>{});
		return *this;
	}
};



/*!存储绑定对象*/
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
		/*! 通过typeid获取type_info,然后将type_info可以存储在type_index中*/
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

/*!当编译器寻在instantiate_bind的重载类型时，它将被强制实例化这个结构*/
template<class Archive, class T>
struct bind_support
{
#if defined(_MSC_VER) && !defined(__clang__)
	/*!windows下面必须是虚函数才能在pre execute main前实例化*/
	virtual void /*DLL_EXPORT_*/ instantiate();
#else // clang or gcc
	static void /*DLL_EXPORT_*/ instantiate();
	typedef instantiate_function_<instantiate> unused;
#endif
};

/*实例化实现*/
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