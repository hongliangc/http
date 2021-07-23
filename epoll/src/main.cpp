#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <thread>
#include <functional>
#include "tls_protocol.h"


#define MAX_LEN  1024
class Client:public tls::CSSLClient
{
	public:
		Client():CSSLClient(){}
		
		void OnRecv(char* buffer, int len) {
			_LOG(logTypeCommon, "Client OnMessage total len:%d, fd:%d", len, m_sock);
		}

		void OnError(int err) {
			_LOG(logTypeCommon, "Client OnError error:%d, fd:%d", err, m_sock);
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

	void Register(callback_ recv, callback_ send) {
		m_recv = recv;
		m_send = send;
	}

	void OnMessage(int fd, char* buffer, int len) {
		_LOG(logTypeCommon, "Server OnMessage total len:%d, fd:%d", len, fd);

		char data[1024 * 4 + 10] = { 0 };
		if (m_send)
		{
			int send_len = m_send(data, sizeof(data));
			_LOG(logTypeCommon, "Server Send len:%d, fd:%d", send_len, fd);
		}
	}

	void OnError(int err) {
		_LOG(logTypeCommon, "Server OnError error:%d", err);
	}
};

int main()
{

	//static_assert(std::is_member_function_pointer<decltype(&Server::Register)>::value,"T::Register is not a member function.");
#if 1
	std::shared_ptr<tls::CSSLServer<tls::Channel<Server>>> m_sslserver = std::make_shared<tls::CSSLServer<tls::Channel<Server>>>();
	std::thread([m_sslserver]() {
		m_sslserver->Initialize("127.0.0.1", 8080);
	}).detach();

	std::vector<std::thread> m_vecThread;
	for (int i = 0; i < 10; i++)
	{
		std::thread thread([]() {
			do 
			{
				std::this_thread::sleep_for(std::chrono::seconds(1));
				std::shared_ptr<Client> m_sslclient = std::make_shared<Client>();
#if 0
				m_sslclient->Initialize("127.0.0.1", 8080);
				for (int coun = 0; coun < 10; coun++)
				{
					char buffer[1024 * 4 + 10] = { 0 };
					m_sslclient->SendData(buffer, sizeof(buffer));
					std::this_thread::sleep_for(std::chrono::seconds(1));
				}
#else
				for (int coun = 0; coun < 10; coun++)
				{
					m_sslclient->Initialize("127.0.0.1", 8080);
					char buffer[1024 * 4 + 10] = { 0 };
					m_sslclient->SendData(buffer, sizeof(buffer));
					std::this_thread::sleep_for(std::chrono::seconds(1));
					m_sslclient->Destroy();
				}
#endif
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