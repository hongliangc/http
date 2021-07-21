#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <thread>
#include <functional>
#include "tls_protocol.h"
using namespace std;
using namespace tls;


#define MAX_LEN  1024
class Client
{
	using callback_ = std::function<int(char*, int)>;
	public:
		callback_ m_recv;
		callback_ m_send;
	public:
		Client() {}
		bool TryAgain(int err)
		{
			if (err == 0)
			{
				return true;
			}
#ifdef HW_OS_WIN
			return (err == WSAEWOULDBLOCK);
#else HW_OS_LINUX
			return (err == EWOULDBLOCK || err == EAGAIN);
#endif
		}

		void Register(callback_ recv, callback_ send) {
			m_recv = recv;
			m_send = send;
		}

		void OnMessage(int fd) {
			char buff[MAX_LEN];
			int total = 0;
			do
			{
				int received = m_recv(buff, MAX_LEN);
				if (received > 0)
				{
					total += received;
				}
				else if (TryAgain(Errno_) == true)
				{
					//_LOG(logTypeCommon, "Server OnMessage TryAgain");
					break;
				}
				else
				{
					_LOG(logTypeCommon, "Server OnMessage error:%d", Errno_);
					break;
				}

			} while (1);
			_LOG(logTypeCommon, "Server OnMessage total len:%d, fd:%d", total, fd);
		}

		void OnError(int errno) {
			_LOG(logTypeCommon, "Server OnError error:%d", errno);
		}
};

class Server
{
	using callback_ = std::function<int(char*, int)>;
public:
	callback_ m_recv;
	callback_ m_send;
public:
	Server() {}
	bool TryAgain(int err)
	{
		if (err == 0)
		{
			return true;
		}
#ifdef HW_OS_WIN
		return (err == WSAEWOULDBLOCK);
#else HW_OS_LINUX
		return (err == EWOULDBLOCK || err == EAGAIN);
#endif
	}

	void Register(callback_ recv, callback_ send) {
		m_recv = recv;
		m_send = send;
	}

	void OnMessage(int fd) {
		char buff[MAX_LEN];
		int total = 0;
		do 
		{
			int received = m_recv(buff, MAX_LEN);
			if (received > 0)
			{
				total += received;
			}
			else if (TryAgain(Errno_) == true)
			{
				//_LOG(logTypeCommon, "Server OnMessage TryAgain");
				break;
			}
			else
			{
				_LOG(logTypeCommon, "Server OnMessage error:%d", Errno_);
				break;
			}

		} while (1);
		_LOG(logTypeCommon, "Server OnMessage total len:%d, fd:%d", total, fd);
	}

	void OnError(int errno) {
		_LOG(logTypeCommon, "Server OnError error:%d", errno);
	}



};

int main()
{

	//static_assert(std::is_member_function_pointer<decltype(&Server::Register)>::value,"T::Register is not a member function.");
#if 1
	std::shared_ptr<CSSLServer<Channel<Server>>> m_sslserver = std::make_shared<CSSLServer<Channel<Server>>>("127.0.0.1", 8080);
	std::thread([m_sslserver]() {
		m_sslserver->Initialize();
	}).detach();

	std::vector<std::thread> m_vecThread;
	for (int i = 0; i < 100; i++)
	{
		std::thread thread([]() {
			do 
			{
				this_thread::sleep_for(std::chrono::seconds(1));
				std::shared_ptr<CSSLClient> m_sslclient = std::make_shared<CSSLClient>("127.0.0.1", 8080);
				m_sslclient->Initialize();
				for (int coun = 0; coun < 10; coun++)
				{
					char buffer[1024 * 4 + 10] = { 0 };
					m_sslclient->SendData(buffer, sizeof(buffer));
					this_thread::sleep_for(std::chrono::seconds(1));
				}
			} while (1);
		});
		m_vecThread.emplace_back(std::move(thread));
	}
	for (auto &i:m_vecThread)
	{
		i.join();
	}
#else
	std::unique_ptr<TaskQueue> task_queue(new ThreadPool());
	do 
	{
		for (int i = 0; i < 20; i++)
		{
			task_queue->Enqueue([i]() {
				_LOG(logTypeCommon, "work run id:%d", i);
			});
		}
		this_thread::sleep_for(std::chrono::seconds(1));
	} while (1);
#endif
	return 0;
}