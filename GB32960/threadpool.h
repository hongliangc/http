#pragma once
#include <functional>
#include <memory>
#include <thread>
#include <vector>
#include <list>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <iostream>
using namespace std;
#if 0

static int gCount = 0;
using job = std::function<void()>;
class TaskQueue
{
public:
	TaskQueue() = default;
	virtual ~TaskQueue() = default;
	virtual void enqueue(job) = 0;
	virtual void shutdown() = 0;
protected:
private:
};

class ThreadPool : public TaskQueue
{
public:
	explicit ThreadPool(int num) :m_shutdown(false)
	{
		while (num-- > 0) {
			m_threads.emplace_back(worker(*this, num));
		}
	};
	ThreadPool(const ThreadPool &) = delete;
	virtual ~ThreadPool() override = default;
	void enqueue(job j) override {
		std::unique_lock<std::mutex> lock(m_mutex);
		m_jobs.emplace_back(j);
		m_cond.notify_one();
	}
	void shutdown() override {
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			printf("shutdown all thread!\n");
			m_shutdown = true;
		}
		m_cond.notify_all();
		for (auto &t : m_threads) {
			t.join();
		}
		m_jobs.clear();
	}

private:
	struct worker {
		worker(ThreadPool &pool, int index) :m_pool(pool), index_(index) {}
		void operator()() {
			stringstream buf;
			int id = 0;
			std::this_thread::get_id()._To_text(buf);
			buf >> id;
			do
			{
				printf("thread:%d,waitting for job\n", index_);
				std::unique_lock<std::mutex> lock(m_pool.m_mutex);
				m_pool.m_cond.wait(lock, [&] {	return !m_pool.m_jobs.empty() || m_pool.m_shutdown;	});
				if (!m_pool.m_jobs.empty())
				{
					auto call = m_pool.m_jobs.front();
					call();
					m_pool.m_jobs.pop_front();
					printf("thread:%d,finish job times:%d\n", index_, ++gCount);
				}
			} while (!m_pool.m_shutdown);
			printf("********************* thread:%d, over\n", index_);
		}
		ThreadPool &m_pool;
		int index_;
	};
	friend struct worker;
	std::vector<std::thread> m_threads;
	std::mutex	m_mutex;
	std::condition_variable m_cond;
	std::list<job>	m_jobs;
	bool m_shutdown;
};
#else
class TaskQueue {
public:
	TaskQueue() = default;
	virtual ~TaskQueue() = default;
	virtual void enqueue(std::function<void()> fn) = 0;
	virtual void shutdown() = 0;
};

class ThreadPool : public TaskQueue {
public:
	explicit ThreadPool(size_t n) : shutdown_(false) {
		while (n) {
			threads_.emplace_back(worker(*this));
			n--;
		}
	}

	ThreadPool(const ThreadPool &) = delete;
	~ThreadPool() override = default;

	void enqueue(std::function<void()> fn) override {
		std::unique_lock<std::mutex> lock(mutex_);
		jobs_.emplace_back(fn);
		cond_.notify_one();
	}

	void shutdown() override {
		// Stop all worker threads...
		{
			std::unique_lock<std::mutex> lock(mutex_);
			printf("shutdown all thread!\n");
			shutdown_ = true;
		}

		cond_.notify_all();

		// Join...
		for (auto &t : threads_) {
			t.join();
		}
	}

private:
	struct worker {
		explicit worker(ThreadPool &pool) : pool_(pool) {}

		void operator()() {

			stringstream buf;
			int id = 0;
			std::this_thread::get_id()._To_text(buf);
			buf >> id;
			for (;;) {
				std::function<void()> fn;
				{
					std::unique_lock<std::mutex> lock(pool_.mutex_);

					pool_.cond_.wait(lock
						//, [&]()->bool {
						//printf("thread id:%d waiting!\n", id);
						//if (/*!pool_.jobs_.empty() ||*/ pool_.shutdown_){
						//	printf("thread id:%d no waiting!\n", id);
						//}
						//return /*!pool_.jobs_.empty()||*/pool_.shutdown_; }
					);

					if (pool_.shutdown_ && pool_.jobs_.empty()) { 
						printf("thread id:%d exist!\n", id);
						break; }
					printf("thread id:%d call!\n", id);
					fn = pool_.jobs_.front();
					pool_.jobs_.pop_front();
				}
				fn();
			}
		}

		ThreadPool &pool_;
	};
	friend struct worker;

	std::vector<std::thread> threads_;
	std::list<std::function<void()>> jobs_;

	bool shutdown_;

	std::condition_variable cond_;
	std::mutex mutex_;
};
#endif