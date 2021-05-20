#pragma once

template<class T>
class TSingleton
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
	class LockGuard
	{
	public:
		LockGuard(std::mutex & m) : lock(m) {}
	private:
		std::unique_lock<std::mutex> lock;
	};

	static LockGuard lock()
	{
		static std::mutex instanceMutex;
		return LockGuard{ instanceMutex };
	}

	TSingleton() = delete;
	TSingleton(TSingleton &obj) = delete;
public:
	static T &instance;
};
template<class T> T &TSingleton<T>::instance = TSingleton<T>::Create();