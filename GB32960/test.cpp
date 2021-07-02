#include "Common.h"

#ifdef DELEGATE


#include <functional>
#include <utility>
#include <array>
#include <tuple>
#include <type_traits>
#include <memory>
#include <iostream>
#include <map>
#include <vector>
#include <stack>
#include <queue>
#include "threadpool.h"
#include "alg.h"

#define ENTT_NOEXCEPT
using namespace std;

class classB {
public:
	template < class iB>
	class innerB {
	public:
		iB& ib;
		innerB(iB b):ib(b) {}
	};

	template<template <class> class classShell, class iB>
	static classShell<iB>* createInnerBs(iB& b) {
		// this function creates instances of innerB and its subclasses, 
		// because B holds a certain allocator
		return new classShell<iB>(b);
	}
};

template<class A>
class classA {
	// intention of this class is meant to be a pluggable interface
	// using templates for compile-time checking
public:
	template <class iB>
	class innerA : A::template innerB<iB>{
	public:
		innerA(iB& b):A::template innerB<iB>(b) {}
	};

	template<class iB>
	static inline innerA<iB>* createInnerAs(iB& b) {
		//return A::createInnerBs<classA<A>::template innerA<>, iB>(b); // line 32: error occurs here
		return A::template createInnerBs<innerA>(b);
	}
};

typedef classA<classB> usable;

template <typename>
class TDelegate;

template<typename Ret, typename ..._Args>
class TDelegate<Ret(_Args...)>
{
public:
	using proto_fn_type = Ret(void *, _Args...);
	TDelegate() = default;

	template<typename T, Ret(T::*method)(_Args...)>
	void connect(T *instance)
	{
		m_payload = instance;
		//没有捕获任何变量的Lambda可以用作值类型模板实参
		m_fn = [](void *payload, _Args... args)->Ret {
			T *data = static_cast<T*>(payload);
			return (data->*method)(std::forward<_Args>(args)...);
		};
	}

	template<class T, Ret(T::*method)(_Args...) const>
	void connect(T *instance)
	{
		m_payload = instance;
		m_fn = [](void *payload, _Args... args)->Ret {
			T* data = static_cast<T*>(payload);
			return (data->*method)(std::forward<_Args>(args)...);
		};
	}


	template<Ret(*method)(_Args...)>
	void connect()
	{
		m_payload = NULL;
		m_fn = [](void *payload, _Args... args)->Ret {
			return (method)(std::forward<_Args>(args)...);
		};
	}

	Ret operator()(_Args... args)
	{
		return m_fn(m_payload, std::forward<_Args>(args)...);
	}
private:
	proto_fn_type *m_fn;
	void *m_payload;
};


void display(int a) {
	printf("display :%d\n", a);
}
// void display() {
// 	printf("display Zero\n");
// }


class Test {
public:
	void Fun(int i) const { cout << i << endl; }
	void Fun1(int i, int j) { cout << i + j << endl; }

	int Fun2(int a, int b, int c) {
		return a + b + c;
	}

	Test() { m = 10; }
	Test(const Test &a) = delete;
	Test(Test &&a) = default;
	Test &operator = (const Test &a) = delete;

	int m;
};



template <typename T, typename Tail> // Tail will be a UnionNode too.
struct UnionNode : public Tail {
	// ...
	template<typename U> struct inUnion {
		// Q: where to add typename/template here?
		typedef typename Tail::template inUnion<U> dummy;
		//typedef Tail::inUnion<U> dummy;
	};
	template< > struct inUnion<T> {
	};
};
template <typename T> // For the last node Tn.
struct UnionNode<T, void> {
	// ...
	template<typename U> struct inUnion {
		char fail[-2 + (sizeof(U) % 2)]; // Cannot be instantiated for any U
	};
	template< > struct inUnion<T> {
	};
};



/*成员对象调用*/
struct _Imp_MemObj
{
	template<class _callable, class _obj>
	static auto _Call(_callable &&call, _obj &&obj)
		->decltype((forward<_obj>(obj).*call))
	{
		return ((forward<_obj>(obj).*call));
	}

	template<class _callable, class _obj>
	static auto _Call(_callable &&call, _obj &&obj)
		->decltype((forward<_obj>(obj)->*call))
	{
		return ((forward<_obj>(obj)->*call));
	}
};

/*成员函数调用*/
struct _Imp_MemFunc
{
	template<class _callable, class _obj,class... _Args>
	static auto _Call(_callable &&call, _obj &&obj, _Args&& ...args)
		->decltype((forward<_obj>(obj).*call)(forward<_Args>(args)...))
	{
		return ((forward<_obj>(obj).*call)(forward<_Args>(args)...));
	}

	template<class _callable, class _obj, class... _Args>
	static auto _Call(_callable &&call, _obj &&obj, _Args&& ...args)
		->decltype((forward<_obj>(obj)->*call)(forward<_Args>(args)...))
	{
		return ((forward<_obj>(obj)->*call)(forward<_Args>(args)...));
	}
};

/*普通函数调用*/
struct _Imp_Func
{
	template<class _callable, class... _Args>
	static auto _Call(_callable&& call, _Args&& ...args)
		->decltype(std::forward<_callable>(call)(std::forward<_Args>(args)...))
	{
		return std::forward<_callable>(call)(std::forward<_Args>(args)...);
	}
};

template<class _callable, 
	class _ty1,
	class decay = typename decay<_callable>::type,
	bool is_pmf = is_member_function_pointer<decay>::value,
	bool is_pmd = is_member_object_pointer<decay>::value>
struct _Function1;

template<class _callable,
	class _ty1,
	class _decay>
	struct _Function1<_callable, _ty1, _decay, true, false>
	: _Imp_MemFunc
{};

template<class _callable,
	class _ty1,
	class _decay>
	struct _Function1<_callable, _ty1, _decay, false, true>
	: _Imp_MemObj
{};

template<class _callable,
	class _ty1,
	class _decay>
	struct _Function1<_callable, _ty1, _decay, false, false>
	: _Imp_Func
{};

/*定义基础模板*/
template<class _callable, 
	class ..._Args>
struct _Function;

/*无参数，是普通函数*/
template<class _callable>
struct _Function<_callable>:_Imp_Func
{};

template<class _callable, 
	class _ty1, 
	class ..._Args>
struct _Function<_callable,_ty1,_Args...>
	:_Function1<_callable,_ty1>
{};


template<class _callable, class ..._Args>
auto _Invoke_(_callable &&call, _Args&& ...args)
->decltype(_Function<_callable, _Args...>::_Call(forward<_callable>(call), forward<_Args>(args)...))
{
	return _Function<_callable, _Args...>::_Call(forward<_callable>(call), forward<_Args>(args)...);
}


template<class T, T v>
struct integral{
	using value_type = T;
	static constexpr value_type value = v;
	constexpr value_type operator()() const	{
		return value;
	}
	operator value_type() const {
		return value;
	}
};

template<int N>
struct factorial:integral<int, N *factorial<N-1>::value>
{};

template<>
struct factorial<0>:integral<int, 1>
{};

template<typename Array, std::size_t... I>
auto a2t_impl(const Array& a, std::index_sequence<I...>)
{
	return std::make_tuple(a[I]...);
}

template<typename T, std::size_t N, typename Indices = std::make_index_sequence<N>>
auto a2t(const std::array<T, N>& a)
{
	return a2t_impl(a, Indices());
}


typedef struct tagPerson
{
	string name;
	int age;
	string city;
}Person, *LPPerson;

vector<Person> vec =
{
	{ "aa",25,"shanghai"},
	{ "bb",24,"beijing" },
	{ "cc",23,"nanjing" },
	{ "dd",26,"nanjing" }
};

/*decltype 获取函数返回值类型，需要构造参数进行调用 */
template<class Fn>
auto groupby(const vector<Person> &v1,const Fn &fn)
->multimap<decltype(fn(*((Person*)0))),Person>
{
	using key_type  = decltype(fn(*((Person*)0)));
	multimap<key_type, Person> map;
	for_each(v1.begin(), v1.end(), [&](const Person &person) {
		map.insert(make_pair(fn(person),person));
	});
	return map;
}

/* 使用result_of 获取返回值，不需要进行构造 */
// template<class Fn>
// multimap<typename result_of<Fn(Person)>::type, Person> groupby(const vector<Person> &v1, const Fn &fn)
// {
// 	using key_type = decltype(fn(*((Person*)0)));
// 	//using key_type = result_of<Fn(Person)>::type;
// 	multimap<key_type, Person> map;
// 	for_each(v1.begin(), v1.end(), [&](const Person &person) {
// 		map.insert(make_pair(fn(person), person));
// 	});
// 	return map;
// }

// 普通函数
void TestFunc()
{
	static int num = 0;
	printf("TestFunc num:%d\n", num++);
}


#include <atomic>
#include <chrono>
#include <stdio.h>
#define NUM 5000
std::atomic_flag g_lock = ATOMIC_FLAG_INIT;
std::mutex g_mutex;

unsigned  long long gCritical = 0;
void test_atomiclock(int i)
{
	while (gCritical < NUM)
	{
		while (g_lock.test_and_set(std::memory_order_acquire)) 
		{
			this_thread::yield();
		}
		gCritical++;
		printf("thread:%d,gCount:%lld\n", i, gCritical);
		g_lock.clear(std::memory_order_release);
	}
}

void test_mutex(int i)
{
	while (gCritical < NUM)
	{
		std::unique_lock<std::mutex> lock(g_mutex);
		gCritical++;
		printf("thread:%d,gCount:%lld\n", i, gCritical);
	}
}

//using AdjacentMatrix = map<int, vector<int>>;
#define MAX 8
int matrix[MAX][MAX] = {
	{ 0,1,1,0,0,0,0,0 },
	{ 0,0,0,1,1,0,0,0 },
	{ 0,0,0,0,0,1,1,0 },
	{ 0,1,0,0,0,0,0,1 },
	{ 0,1,0,0,0,0,0,1 },
	{ 0,0,1,0,0,0,0,1 },
	{ 0,0,1,0,0,0,0,1 },
	{ 0,0,0,1,1,1,1,0 },
};




void Depth()
{
	bool bVisit[MAX] = { false };
	stack<int> s;
	s.push(0);
	bVisit[0] = true;
	printf("Depth: %d ", s.top());
	while (!s.empty())
	{
		int id = s.top();
		int i = 0;
		for (; i < MAX; i++)
		{
			if (matrix[id][i] == 1 && bVisit[i] == false)
			{
				s.push(i);
				bVisit[i] = true;
				printf("%d ", i);
				break;
			}
		}
		if (i == MAX)
		{
			s.pop();
		}
	}
}

void Breadth()
{
	bool bVisit[MAX] = { false };
	queue<int> q;
	q.push(0);
	bVisit[0] = true;
	printf("Breadth: %d ", q.front());
	while (!q.empty())
	{
		int id = q.front();
		q.pop();
		for (int i = 0; i < MAX; i++)
		{
			if (matrix[id][i] == 1 && bVisit[i] == false)
			{
				q.push(i);
				bVisit[i] = true;
				printf("%d ", i);
			}
		}
	}
}


//dp 三角问题
int triangle[4][4] = {
	{ 2, 0, 0, 0 },
	{ 3, 4, 0, 0 },
	{ 6, 5, 7, 0 },
	{ 4, 1, 8, 3 },
};
//dp状态转换方程



/* 测试std::move(将左值转化为右值) 和std::forwad */
//void overloaded(int &arg) { std::cout << "by lvalue\n"; }
void overloaded(int const &arg) { std::cout << "by const lvalue\n"; }
void overloaded(int && arg) { std::cout << "by rvalue\n"; }

template< typename t >
/* "t &&" with "t" being template param is special, and  adjusts "t" to be
(for example) "int &" or non-ref "int" so std::forward knows what to do. */
void forwarding(t && arg) {
	std::cout << "via std::forward: ";
	overloaded(std::forward< t >(arg));
	std::cout << "via std::move: ";
	overloaded(std::move(arg)); // conceptually this would invalidate arg
	std::cout << "by simple passing: ";
	overloaded(arg);
}

void _test_forward() {
	std::cout << "initial caller passes rvalue:\n";
	forwarding(5);
	std::cout << "initial caller passes lvalue:\n";
	int x = 5;
	forwarding(x);
}

int main() {

	//_test_forward();
	////travers
	//Depth();
	//Breadth();

	////测试原子锁（spin lock）和互斥锁的效率，
	//auto start = std::chrono::high_resolution_clock::now();
	//std::vector<std::thread> m_thread;
	//for (int i = 0; i < 10; i++)
	//{
	//	m_thread.push_back(std::thread(test_mutex, i));//5326ms
	//	//m_thread.push_back(std::thread(test_atomiclock,i));//8026ms
	//}
	//for (auto &th: m_thread)
	//{
	//	th.join();
	//}
	//auto end = std::chrono::high_resolution_clock::now();
	//auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	//printf("atomic flag cost time:%lld\n", interval.count());
	//测试
	ThreadPool tp(10);
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	for (int i = 0; i < 20; i++)
	{
		tp.enqueue(TestFunc);
	}
	std::this_thread::sleep_for(std::chrono::seconds(2));
	tp.shutdown();
	//std::shared_ptr<char> pStr = std::make_shared<char>(10);
	//memset(pStr.get(), 0x00, 10);
	//memcpy(pStr.get(), "111", strlen("111"));
	//cout << "11111111:" << pStr.get() << endl;
	////lambda can capture contexts
	//auto lamb = [&]()
	//{
	//	cout << "333333333:" << pStr.get() << endl;
	//};
	//memcpy(pStr.get(), "222", strlen("222"));
	//cout << "22222222:" << pStr.get() << endl;
	//lamb();

	////sort
	//int arr[] = { 4,6,8,5,9,4,5,8 };
	//CSort::MinHeapSort(arr, 8);
	//CSort::MaxHeapSort(arr, 8);


	/*decltype在编译器就可以获取表达式返回类型不用运算，如果lvalue包含括号为引用，
	例如 int val = 1, decltype((val)）返回类型为int &*/
	int iA = 1;
	decltype((iA)) tmpA = iA;
	tmpA++;
	/*需要特别注意，表达式内容为解引用操作，dclTempB为一个引用，引用必须初始化，故编译不过*/
	int *pA = &iA;
	decltype(*pA) temPa = iA;
	temPa++;

	//通过返回类型进行排序,
	auto res = groupby(vec, [](const Person &p) { return p.age; });

	for_each(res.begin(), res.end(), [](decltype(res)::value_type &p) {
		cout << p.second.name << " " << p.second.city << "  " << p.second.age << endl;
	});


	std::array<int, 10> arr1 = { 1, 2, 3, 4, 5, 5, 2, 3, 4, 1 };
	auto result = std::invoke(a2t<int, 10>, arr1);

	int a = 5;
	usable::innerA<int>* myVar = usable::createInnerAs(a);


	Test t;
	using t1 = decay<decltype(&Test::Fun)>::type;
	//_Is_memfunptr 判断是否为成员函数
	bool result0 = std::is_base_of<_Is_memfunptr<t1>::_Class_type, decay<decltype(t)>::type>::value;
	using t2 = decay<decltype(&Test::m)>::type;
	//_Is_member_object_pointer 判断是否为对象
	bool result1 = std::is_base_of<_Is_member_object_pointer<t2>::_Class_type, decay<decltype(t)>::type>::value;
	bool result2 = std::is_base_of<t2, Test>::value;


	using t3 = std::result_of<decltype(display)&(int)>::type;
	bool result3 = std::is_same<t3, decltype(display)>::value;
	result3 = std::is_same<t3, decltype(display(1))>::value;

	//std::invoke(&Test::Fun, t, 1);
	//auto ret = std::invoke(&Test::m, t);
	_Invoke_(&Test::Fun, t, 1);
	_Invoke_(&Test::Fun, &t, 2);
	_Invoke_([]() {printf("hello world!\n"); });
	_Invoke_(display, 2);
	auto ret = _Invoke_(&Test::m, t);
	ret = _Invoke_(&Test::m, &t);



	static_assert(std::is_member_function_pointer<decltype(&Test::Fun)>::value,
		"A::member is not a member function.");
	class cls {};
	std::cout << (std::is_member_object_pointer<decltype(&Test::m)>::value
		? "T is member object pointer"
		: "T is not a member object pointer") << '\n';
	std::cout << (std::is_member_object_pointer<decltype(&Test::Fun)>::value
		? "T is member object pointer"
		: "T is not a member object pointer") << '\n';

	using  Two = integral<int, 2>;
	integral<int, 4> Four;
	cout << Two::value << "," << (int)Four <<",factorial<5>:"<< factorial<5>::value << endl;
	
	//编译时的断言错误
	//static_assert((Two::value == Four.value), "four is not equal two");


	TDelegate<int(int, int, int)> inst1;
	inst1.connect<Test,&Test::Fun2>(&t);
	auto retult = inst1(1, 2, 3);

	TDelegate<void(int)> inst2;
	inst2.connect<Test, &Test::Fun>(&t);
	inst2(1);

	TDelegate<void(int)> fn;
	fn.connect<&display>();
	fn(0);

	system("pause");
	return 0;
}

#endif