#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <thread>
#include <functional>
#include "tls_protocol.h"
using namespace std;



int main()
{
	std::shared_ptr<CSSLServer> m_sslserver = std::make_shared<CSSLServer>("127.0.0.1", 8080);
	std::thread([m_sslserver]() {
		m_sslserver->Initialize();
	}).detach();



	this_thread::sleep_for(std::chrono::seconds(1));
	std::shared_ptr<CSSLClient> m_sslclient = std::make_shared<CSSLClient>("127.0.0.1", 8080);
	m_sslclient->Initialize();
	int32_t count = 0;
	do
	{
		string data = format("test ssl client count :%d", count);
		m_sslclient->SendData((char*)data.data(), data.length());
		this_thread::sleep_for(std::chrono::seconds(5));
	} while (1);
	return 0;
}