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

// Checks that collections have equal size and all elements are the same
// template <class T> inline
// void check_collection(T const & a, T const & b)
// {
// 	auto aIter = std::begin(a);
// 	auto aEnd = std::end(a);
// 	auto bIter = std::begin(b);
// 	auto bEnd = std::end(b);
// 
// 	CHECK_EQ(std::distance(aIter, aEnd), std::distance(bIter, bEnd));
// 
// 	for (; aIter != aEnd; ++aIter, ++bIter)
// 		CHECK_EQ(*aIter, *bIter);
// }
// 
// template <class T> inline
// void check_ptr_collection(T const & a, T const & b)
// {
// 	auto aIter = std::begin(a);
// 	auto aEnd = std::end(a);
// 	auto bIter = std::begin(b);
// 	auto bEnd = std::end(b);
// 
// 	CHECK_EQ(std::distance(aIter, aEnd), std::distance(bIter, bEnd));
// 
// 	for (; aIter != aEnd; ++aIter, ++bIter)
// 		CHECK_EQ(**aIter, **bIter);
// }

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
template <template <class> class DERIVED, class VALUE> class base1 {
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
	/*******/
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
		//!!!!!!!!!!!! 如果dataReady 不在锁下面，可以condVar.wait处于死锁 !!!!!!!!!!!!!!!!!!!!!!!
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