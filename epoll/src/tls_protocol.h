#pragma once
#include "utility.h"
extern "C"{
#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"
}
#include <errno.h>

#ifdef _WIN32
#define Errno_ GetLastError()
#else
#define Errno_ (errno)
#endif

#ifdef _WIN32
#define _ROOT_CA_				hw_string::getAppDirectory() + "serverca.crt"

#define _SERVER_CA_				hw_string::getAppDirectory() + "server.crt"
#define _SERVER_KEY_			hw_string::getAppDirectory() + "server.pem"

#define _CLIENT_CA_				hw_string::getAppDirectory() + "client.crt"
#define _CLIENT_KEY_			hw_string::getAppDirectory() + "client.pem"
#else

#define _ROOT_CA_				"serverca.crt"

#define _SERVER_CA_				"server.crt"
#define _SERVER_KEY_			"server.pem"

#define _CLIENT_CA_				"client.crt"
#define _CLIENT_KEY_			"client.pem"
#endif

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

using socket_ = SOCKET;
#else
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <netdb.h>

using socket_ = int;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

#define CHECK_INITIAL_STATE(x)	\
if (x == false)					\
{								\
	return false;				\
}	

typedef struct tagStruSslData
{
	char		 *m_buf;
	unsigned int  m_len;
	tagStruSslData()
	{
		m_buf = NULL;
		m_len = 0;
	}
}StruSslData, *LPStruSslData;

template<typename T>
class Channel;

class ISSLSession
{
public:
	class SSLInit {
	public:
		SSLInit() {
			SSL_library_init();
			OpenSSL_add_all_algorithms();
			SSL_load_error_strings();
		}
	};
public:
	using ListData = std::list<std::shared_ptr<StruSslData>>;
	using DataCb = std::function<int(char*, int, int)>;
	using Fn_init = std::function<bool(socket_ sock, const struct addrinfo &ai)>;
	struct SslDeleter {
		void operator()(SSL *_p){
			SSL_shutdown(_p);
			SSL_free(_p);
		}

		void operator()(SSL_CTX *_p){
			SSL_CTX_free(_p);
		}
	};
	using UniqueSslPtr = std::unique_ptr<SSL, SslDeleter>;
	using UniqueCtxPtr = std::unique_ptr<SSL_CTX, SslDeleter>;
public:
	ISSLSession(std::string host, uint32_t port) :m_sock(INVALID_SOCKET), m_host(host), m_port(port), m_status(false) {}
	virtual ~ISSLSession(){}
	virtual socket_ CreateSocket(string host, int port, Fn_init fn)
	{
		struct addrinfo hint, *result;
		memset(&hint, 0x00, sizeof(addrinfo));
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_family = AF_UNSPEC;
		hint.ai_flags = 0;
		hint.ai_protocol = 0;
		auto service = std::to_string(port);
		if (getaddrinfo(host.data(), service.data(), &hint, &result) == 0)
		{
			for (auto node = result; node != NULL; node = node->ai_next)
			{
				auto sock = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
				if (sock == INVALID_SOCKET) {
					continue;
				}

				int val = 1;
				setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&val, sizeof(val));
				if (fn(sock, *node)) {
					freeaddrinfo(result);
					m_sock = sock;
					return m_sock;
				}
			}
		}
		else
		{
			_LOG(logTypeCommon, "getaddrinfo failed! erron:%d", errno);
		}
		freeaddrinfo(result);
		return INVALID_SOCKET;
	}
	void CloseSocket(socket_ sock)
	{
		closesocket(sock);
	}

	void set_nonblock(socket_ sock, bool nonblock)
	{
#ifdef _WIN32
		auto flags = nonblock ? 1UL : 0UL;
		ioctlsocket(sock, FIONBIO, &flags);
#else
		auto flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, nonblock ? (flags | O_NONBLOCK) : (flags &(~O_NONBLOCK)));
#endif
	}


	int OnRecv(char *data, int len)
	{
		if (m_datacb)
		{
			return m_datacb(data, len, 0);
		}
		return 0;
	}

	int OnError()
	{
		if (m_datacb)
		{
			m_datacb(NULL, 0, Errno_);
		}
		//Destroy();
		return 0;
	}

	bool TryAgain(int err)
	{
		if (err == 0)
		{
			return true;
		}
#ifdef _WIN32
		return (err == WSAEWOULDBLOCK);
#else
		return (err == EWOULDBLOCK || err == EAGAIN);
#endif
	}

	bool Connection_Error(int err) {
#ifdef _WIN32
		return err != WSAEWOULDBLOCK;
#else
		return err != EINPROGRESS;
#endif
	}

	void Destroy()
	{
		if (m_sock != INVALID_SOCKET)
		{
			closesocket(m_sock);
			m_sock = INVALID_SOCKET;
		}
		m_port = 0;
		m_host = "";
		m_status = false;
	}


protected:
	socket_ m_sock;
	int32_t m_port;
	string m_host;
	bool m_status;
	DataCb m_datacb;
	UniqueCtxPtr m_ctx;
};

class CSSLClient :public ISSLSession
{
public:
	CSSLClient(std::string host,uint32_t port):ISSLSession(host, port){}
	~CSSLClient(){}

	bool SendData(char* data, int len)
	{
		if (data == NULL || len <= 0)
		{
			_LOG(logTypeCommon, "SendData param error");
			return false;
		}
		StruSslData *pData = new StruSslData;
		pData->m_len = len;
		pData->m_buf = new char[pData->m_len + 1];
		std::shared_ptr<StruSslData> elemet(pData, [=](StruSslData*data) {
			FREE_ARR(data->m_buf);
			FREE_PTR(data);
		});
		memcpy(pData->m_buf, data, len);

		std::unique_lock<std::mutex> lock(m_mutex);
		m_listData.push_back(elemet);
		return true;
	}

	ListData GetData()
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		ListData data = std::move(m_listData);
		m_listData.clear();
		return std::move(data);
	}

	void RunTask()
	{
		set_nonblock(m_sock, true);
		try
		{
			fd_set rfd;
			while (m_status)
			{
#if 0
				do
				{
					/*!需要设置为非阻塞*/
					char buf[1024] = { '\0' };
					int len = SSL_read(m_ssl.get(), buf, sizeof(buf));
					if (len > 0) {
						_LOG(logTypeCommon, "CSSLClient SSL_read len:%d", len);
						OnRecv(buf, len);
					}
					else {
						if (TryAgain(Errno_) == true)
						{
							this_thread::sleep_for(std::chrono::milliseconds(1000));
							_LOG(logTypeCommon, "CSSLClient SSL_read no data");
							break;
						}
						else
						{
							OnError();
							_LOG(logTypeCommon, "CSSLClient SSL_read failed! erron:%d", Errno_);
							return;
						}
					}
				} while (1);
#else
				do
				{
					const int readSize = 1024;
					char *rc = NULL;
					int received, count = 0;
					fd_set fds;
					struct timeval timeout;

					char buffer[1024] = { '\0' };
					/*!需要设置为非阻塞,同线程可以发送数据*/
					received = SSL_read(m_ssl.get(), buffer, readSize);
					if (received > 0)
					{
						_LOG(logTypeCommon, "CSSLClient SSL_read len:%d", received);
						OnRecv(buffer, received);
					}
					else
					{
						int err = SSL_get_error(m_ssl.get(), received);
						switch (err)
						{
						case SSL_ERROR_ZERO_RETURN:
							// peer disconnected...
							_LOG(logTypeCommon, "CSSLClient SSL_ERROR_ZERO_RETURN error:%d", Errno_);
							OnError();
							return;
						case SSL_ERROR_WANT_READ:
							// no data available right now, wait a few seconds in case new data arrives...
							if (SSL_get_rfd(m_ssl.get()) == m_sock)
							{
								FD_ZERO(&fds);
								FD_SET(m_sock, &fds);
								timeout.tv_sec = 0;
								timeout.tv_usec = 500*1000;
								err = select(m_sock + 1, &fds, NULL, NULL, &timeout);
								if (err > 0)
									continue;
								if (err == 0) {
								}
								else {
									OnError();
									return;
								}
								break;
							}
						}
					}
				} while (0);
#endif
				if (m_listData.size() > 0)
				{
					std::unique_lock<std::mutex> lock(m_mutex);
					_LOG(logTypeCommon, "CSSLClient SSL_write m_listData size:%d", m_listData.size());
					for (auto iter = m_listData.begin(); iter != m_listData.end(); )
					{
						StruSslData *data = (*iter).get();
						int offset = 0;
						int try_count = 0;
						do
						{
							int ret = SSL_write(m_ssl.get(), data->m_buf + offset, data->m_len - offset);
							if (ret > 0)
							{
								offset += ret;
							}
							else
							{
								if (TryAgain(Errno_) == true)
								{
									this_thread::sleep_for(std::chrono::milliseconds(5));
									_LOG(logTypeCommon, "CSSLClient SSL_write failed! try_count:%d", try_count++);
									continue;
								}
								else
								{
									OnError();
									_LOG(logTypeCommon, "CSSLClient SSL_write failed! erron:%d", Errno_);
									return;
								}
							}
						} while (offset < data->m_len && try_count < 3);
						if (offset == data->m_len)
						{
							iter = m_listData.erase(iter);
							_LOG(logTypeCommon, "CSSLClient SSL_write success len:%d", offset);
						}
					}
				}
			}

		}
		catch (const std::exception& e)
		{
			_LOG(logTypeCommon, "CSSLClient RunTask catch exception:%s", e.what());
		}
	}

	SSL_CTX* SSLInitCtx()
	{
		SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
		if (ctx == NULL)
		{
			ERR_print_errors_fp(stderr);
			return NULL;
		}

		/*!加载本地根证书*/
		if (SSL_CTX_load_verify_locations(ctx, _ROOT_CA_, NULL) == false)
		{
			SSL_CTX_free(ctx);
			return NULL;
		}

		/*!设置对端检测*/
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		
		return ctx;
	}

	int NonBlockingConnect(SSL* ssl, int seconds)
	{
		_LOG(logTypeCommon, "NonBlockingConnect SSL_connect begin!");
		int ret = -1;
		while (1) {
			_utility::CDataTime timer;
			ret = SSL_connect(ssl);
			if (ret == 1) {
				break;
			}

			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(m_sock, &fds);
			int decodedError = SSL_get_error(ssl, ret);

			if (decodedError == SSL_ERROR_WANT_READ) {
				int result = select(m_sock + 1, &fds, NULL, NULL, NULL);
				if (result == -1) {
					_LOG(logTypeCommon, "NonBlockingConnect SSL_ERROR_WANT_READ error:%d",Errno_);

					decodedError = SSL_get_error(ssl, decodedError);
					ERR_print_errors_fp(stderr);
					_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(decodedError, NULL));
					return ret;
				}
			}
			else if (decodedError == SSL_ERROR_WANT_WRITE) {
				int result = select(m_sock + 1, NULL, &fds, NULL, NULL);
				if (result == -1) {
					_LOG(logTypeCommon, "NonBlockingConnect SSL_ERROR_WANT_WRITE error:%d", Errno_);
					decodedError = SSL_get_error(ssl, decodedError);
					ERR_print_errors_fp(stderr);
					_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(decodedError, NULL));
					return ret;
				}
			}
			else {
				decodedError = SSL_get_error(ssl, decodedError);
				ERR_print_errors_fp(stderr);
				_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(decodedError, NULL));
				return ret;
			}
			if (timer.elapsed<chrono::seconds>() > seconds)
			{
				_LOG(logTypeCommon, "NonBlockingConnect SSL_connect connect timeout");
				return ret;
			}
		}
		return ret;
	}

	bool Initialize()
	{
		try
		{

			Fn_init init = [this](socket_ sock, const struct addrinfo &ai)->bool {

				char ip[32] = { 0 };
				sockaddr_in *server = (sockaddr_in*)(ai.ai_addr);
				inet_ntop(AF_INET, &(server->sin_addr), ip, sizeof(ip));
				_LOG(logTypeCommon, "CSSLClient %s:%d, socket %d\n", ip, ntohs(server->sin_port), sock);
				set_nonblock(sock, true);
				if (::connect(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen)) == -1)
				{
					auto Check = [](socket_ sock, time_t sec, time_t usec)->bool {
						fd_set fdsr;
						FD_ZERO(&fdsr);
						FD_SET(sock, &fdsr);

						auto fdsw = fdsr;
						auto fdse = fdsr;

						timeval tv;
						tv.tv_sec = static_cast<long>(sec);
						tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usec);

						if (select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv) > 0 &&
							(FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))) {
							int error = 0;
							socklen_t len = sizeof(error);
							return getsockopt(sock, SOL_SOCKET, SO_ERROR,
								reinterpret_cast<char *>(&error), &len) >= 0 &&
								!error;
						}
						return false;
					};
					if (Connection_Error(Errno_) || !Check(sock,10, 0))
					{
						_LOG(logTypeCommon, "CSSLClient connect failed! erron:%d", Errno_);
						return false;
					}
				}
				set_nonblock(sock, false);
				return true;
			};
			m_sock = CreateSocket(m_host, m_port, init);
			if (m_sock == INVALID_SOCKET)
			{
				_LOG(logTypeCommon, "CreateSocket failed");
				return false;
			}

			m_ctx = UniqueCtxPtr(SSLInitCtx());
			if (m_ctx.get() == NULL)
			{
				closesocket(m_sock);
				return false;
			}
			m_ssl = UniqueSslPtr(SSL_new(m_ctx.get()));
			if (m_ssl == nullptr)
			{
				ERR_print_errors_fp(stderr);
				_LOG(logTypeCommon, "SSL_new failed");
				closesocket(m_sock);
				return false;
			}
			SSL_set_fd(m_ssl.get(), m_sock);
#if 0
			auto status = NonBlockingConnect(m_ssl.get(), 5);
#else
			auto status = SSL_connect(m_ssl.get());
#endif
			if (status <= 0) {
				status = SSL_get_error(m_ssl.get(), status);
				ERR_print_errors_fp(stderr);
				_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(status, NULL));
				return false;
			}
			else {
				/*!获取检测结果*/
				status = SSL_get_verify_result(m_ssl.get());
				if (status != X509_V_OK) {
					_LOG(logTypeCommon, "SSL_get_verify_result failed errinfo:%s ", ERR_error_string(status, NULL));
					return false;
				}

				auto server_cert = SSL_get_peer_certificate(m_ssl.get());

				if (server_cert == nullptr) { return false; }

				char *subj = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
				_LOG(logTypeCommon, "Subject: %s\n", subj);
				OPENSSL_free(subj);
				char *issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
				_LOG(logTypeCommon, "Issuer: %s\n", issuer);
				OPENSSL_free(issuer);

				X509_free(server_cert);
				_LOG(logTypeCommon, "SSL session conneect");
			}

			m_status = true;
			std::thread([this]() { RunTask(); }).detach();
		}
		catch (const std::exception& e)
		{
			_LOG(logTypeCommon, "CSSLClient Initialize catch exception:%s", e.what());
		}
		return  true;
	}


	bool Destory()
	{
		ISSLSession::Destroy();
	}
public:
	std::mutex m_mutex;
	ListData m_listData;
	UniqueSslPtr m_ssl;
};

//template<typename T>
class CSSLServer:public ISSLSession
{
	using CallBack = std::function<void()>;
public:
	CSSLServer(std::string host, uint32_t port) :ISSLSession(host, port) {}
	~CSSLServer() { }

	void RunTask()
	{
		//set_nonblock(m_sock, true);
		try
		{
			struct sockaddr_in remote_addr;
			while (m_status)
			{
#ifdef _WIN32
				int len = sizeof(struct sockaddr_in);
				memset(&remote_addr, 0x00, sizeof(remote_addr));
				/* 等待客户端连上来 */
				auto sock = accept(m_sock, (struct sockaddr *) &remote_addr, &(int)len);
				if (sock == -1) {
					if (!TryAgain(Errno_))
					{
						_LOG(logTypeCommon, "accept failed err:%d", Errno_);
					}
					this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				char ip[32] = { 0 };
				inet_ntop(AF_INET, &remote_addr.sin_addr, ip, sizeof(ip));
				_LOG(logTypeCommon, "client %s:%d, socket %d\n", ip, ntohs(remote_addr.sin_port), sock);

				auto ssl = shared_ptr<SSL>(SSL_new(m_ctx.get()), [](SSL *_p) {
					SSL_shutdown(_p);
					SSL_free(_p);
				});
				if (ssl == nullptr)
				{
					ERR_print_errors_fp(stderr);
					_LOG(logTypeCommon, "SSL_new failed");
					closesocket(sock);
					continue;
				}
				if (SSL_set_fd(ssl.get(), sock) == 0)
				{
					ERR_print_errors_fp(stderr);
					_LOG(logTypeCommon, "SSL_set_fd failed");
					closesocket(sock);
					continue;
				}
				/* 建立SSL连接 */
				if (SSL_accept(ssl.get()) == -1) {
					_LOG(logTypeCommon, "SSL_accept failed err:%d", Errno_);
					closesocket(sock);
				}
				CallBack callback = [this, ssl]() {
					auto ssl_ = ssl;
					do
					{
						const int readSize = 1024;
						char *rc = NULL;
						int received, count = 0;
						fd_set fds;
						struct timeval timeout;

						char buffer[1024] = { '\0' };
						received = SSL_write(ssl_.get(), buffer, sizeof(buffer));
						if (received > 0)
						{
							_LOG(logTypeCommon, "CSSLServer SSL_write len:%d", received);
						}
						received = SSL_read(ssl_.get(), buffer, readSize);
						if (received > 0)
						{
							_LOG(logTypeCommon, "CSSLServer SSL_read len:%d", received);
							OnRecv(buffer, received);
						}
						else
						{
							if (TryAgain(Errno_) == true)
							{
								this_thread::sleep_for(std::chrono::milliseconds(5));
								continue;
							}
							else
							{
								OnError();
								_LOG(logTypeCommon, "CSSLServer SSL_read failed! erron:%d", Errno_);
								return;
							}
						}


					} while (m_status);
				};
				using T_ = decltype(callback);
				_LOG(logTypeCommon, "CSSLServer 111 fn address:0x%0x!, ssl:0x%0x", &callback, &ssl);
				void* ptr = reinterpret_cast<void *>(&callback);


				std::thread([ptr] () {

					CallBack *fn = reinterpret_cast<CallBack*>(ptr);
					if (fn != NULL)
					{
						(*fn)();
					}
					else
					{
						_LOG(logTypeCommon, "CSSLServer 222 fn address:0x%0x!", ptr);
					}
				}).detach();

				//this_thread::sleep_for(std::chrono::seconds(1));

#else
				socklen_t len = sizeof(struct sockaddr_in);
				int efd = epoll_create(15);
				if (efd == -1)
				{
					_LOG(logTypeCommon, "CSSLServer epoll_create failed err:%d", Errno_);
					OnError();
					return;
				}
				struct epoll_event event;
				event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
				event.data.fd = m_sock;
				//监听socket加入epoll
				int ret = epoll_ctl(efd, EPOLL_CTL_ADD, m_sock, &event);
				if (ret == -1)
				{
					_LOG(logTypeCommon, "CSSLServer epoll_ctl failed err:%d", Errno_);
					OnError();
					return;
				}

				struct epoll_event events[5];
				memset(events, 0, 5 * sizeof(struct epoll_event));

				int ready_num = 0;
				while (m_status) {
					ready_num = epoll_wait(efd, events, 5, 1000);
					if (ready_num > 0) {
						for (int i = 0; i < ready_num; ++i) {
							if (events[i].events & EPOLLRDHUP) {
								_LOG(logTypeCommon, "CSSLServer socket:%d closed", events[i].data.fd);
								epoll_ctl(efd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
								continue;
							}
							//如果对应项的socket为服务端监听socket（22233端口的socket）
							if (events[i].data.fd == m_sock) {
								/* 等待客户端连上来 */
								auto sock = accept(m_sock, (struct sockaddr *) &remote_addr, &len);
								if (sock == -1) {
									if (!TryAgain(Errno_))
									{
										_LOG(logTypeCommon, "CSSLServer accept failed err:%d", Errno_);
									}
									this_thread::sleep_for(std::chrono::milliseconds(10));
									continue;
								}

								char ip[32] = { 0 };
								inet_ntop(AF_INET, &remote_addr.sin_addr, ip, sizeof(ip));
								_LOG(logTypeCommon, "CSSLServer client %s:%d, socket %d\n", ip, ntohs(remote_addr.sin_port), sock);

								auto ssl = shared_ptr<SSL>(SSL_new(m_ctx.get()), [](SSL *_p) {
									SSL_shutdown(_p);
									SSL_free(_p);
								});
								if (ssl == nullptr)
								{
									ERR_print_errors_fp(stderr);
									_LOG(logTypeCommon, "CSSLServer SSL_new failed");
									closesocket(sock);
									continue;
								}
								if (SSL_set_fd(ssl.get(), sock) == 0)
								{
									ERR_print_errors_fp(stderr);
									_LOG(logTypeCommon, "CSSLServer SSL_set_fd failed");
									closesocket(sock);
									continue;
								}
								/* 建立SSL连接 */
								if (SSL_accept(ssl.get()) == -1) {
									_LOG(logTypeCommon, "CSSLServer SSL_accept failed err:%d", Errno_);
									closesocket(sock);
								}
								/*!添加新连接*/
								struct epoll_event client;
								client.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
								CallBack callback = [this, ssl]() {
									//auto ssl_ = ssl;
									do
									{
										_LOG(logTypeCommon, "CSSLServer SSL_read ssl:0x%0x", &ssl);
										/*!需要设置为非阻塞*/
										const int readSize = 1024;
										char buffer[1024] = { '\0' };
										int len = SSL_read(ssl.get(), buffer, readSize);
										if (len > 0) {
											_LOG(logTypeCommon, "CSSLServer SSL_read len:%d", len);
											OnRecv(buffer, len);
										}
										else {
											if (TryAgain(Errno_) == true /*errno ==  EWOULDBLOCK || errno == EAGAIN*/)
											{
												this_thread::sleep_for(std::chrono::milliseconds(1000));
												_LOG(logTypeCommon, "CSSLServer SSL_read no data  len:%d", len);
												break;
											}
											else
											{
												OnError();
												_LOG(logTypeCommon, "CSSLServer SSL_read failed! erron:%d", Errno_);
												return;
											}
										}
									} while (1);
								};

								_LOG(logTypeCommon, "CSSLServer register fn address:0x%0x!, ssl:0x%0x", &callback, &ssl);
								client.data.ptr = reinterpret_cast<void *>(&callback);
								set_nonblock(sock, true);
								epoll_ctl(efd, EPOLL_CTL_ADD, sock, &client);

								std::thread([this, ssl]() {
									do
									{
										const int readSize = 1024;
										char *rc = NULL;
										int received, count = 0;
										char buffer[1024] = { '\0' };
										received = SSL_write(ssl.get(), buffer, sizeof(buffer));
										if (received > 0)
										{
											_LOG(logTypeCommon, "CSSLServer SSL_write len:%d", received);
										}
										this_thread::sleep_for(std::chrono::milliseconds(1000));


									} while (m_status);
								}).detach();

								_LOG(logTypeCommon, "CSSLServer client connected success!");
							}
							else {
								CallBack *fn = reinterpret_cast<CallBack*>(events[i].data.ptr);
								if (fn != NULL)
								{
									(*fn)();
								}
								else
								{
									_LOG(logTypeCommon, "CSSLServer fn address:0x%0x, origin fn:0x%0x!", events[i].data.ptr, fn);
								}
							}
						}
					}
					else if(ready_num == 0)
					{
						_LOG(logTypeCommon, "CSSLServer epoll_wait timeout!");
					}
					else
					{
						_LOG(logTypeCommon, "CSSLServer epoll_wait err:%d!", Errno_);
						std::this_thread::sleep_for(std::chrono::seconds(1));
					}
				}
				close(efd);
#endif
			}

		}
		catch (const std::exception& e)
		{
			_LOG(logTypeCommon, "CSSLServer RunTask catch exception:%s", e.what());
		}
	}

	SSL_CTX* SSLInitCtx()
	{
		SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
		if (ctx == NULL)
		{
			ERR_print_errors_fp(stderr);
			return NULL;
		}

		/* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
		if (SSL_CTX_use_certificate_file(ctx, _SERVER_CA_, SSL_FILETYPE_PEM) <= 0) {
			_LOG(logTypeCommon, "SSL_CTX_use_certificate_file failed!");
			SSL_CTX_free(ctx);
			return NULL;
		}
		/* 载入用户私钥 */
		if (SSL_CTX_use_PrivateKey_file(ctx, _SERVER_KEY_, SSL_FILETYPE_PEM) <= 0) {
			_LOG(logTypeCommon, "SSL_CTX_use_PrivateKey_file failed!");
			SSL_CTX_free(ctx);
			return NULL;
		}
		
		if (!SSL_CTX_check_private_key(ctx)) {
			_LOG(logTypeCommon, "SSL_CTX_check_private_key failed!");
			SSL_CTX_free(ctx);
			return NULL;
		}

		return ctx;
	}

	bool Initialize()
	{
		Fn_init init = [](socket_ sock, const struct addrinfo &ai)->bool {

			char ip[32] = { 0 };
			sockaddr_in *server = (sockaddr_in*)(ai.ai_addr);
			inet_ntop(AF_INET, &(server->sin_addr), ip, sizeof(ip));
			_LOG(logTypeCommon, "CSSLServer %s:%d, socket %d\n", ip, ntohs(server->sin_port), sock);
			if (::bind(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen)) == -1)
			{
				_LOG(logTypeCommon, "CSSLServer bind failed! erron:%d", Errno_);
				return false;
			}
			if (::listen(sock, 10) == -1)
			{
				_LOG(logTypeCommon, "CSSLServer listen failed! erron:%d", Errno_);
				return false;
			}
			return true;
		};
		m_sock = CreateSocket(m_host, m_port, init);
		if (m_sock == INVALID_SOCKET)
		{
			_LOG(logTypeCommon, "CSSLServer CreateSocket failed! erron:%d", Errno_);
			return false;
		}

		m_ctx = UniqueCtxPtr(SSLInitCtx());
		if (m_ctx.get() == NULL)
		{
			_LOG(logTypeCommon, "CSSLServer SSLInitCtx failed!");
			closesocket(m_sock);
			return false;
		}

		m_status = true;
		std::thread([this]() { RunTask(); }).detach();
		return  true;
	}

	bool Destory()
	{
		ISSLSession::Destroy();
	}
};


template<typename T>
class Channel
{
	using CallBack_ = std::function<void()>;
public:
	CallBack_ read_;
	CallBack_ write_;
	CallBack_ connect_;
	CallBack_ error_;
	T* m_proxy;
public:
	Channel(T *obj):m_proxy(obj) {
		read_ = std::bind(&T::HandleRead, m_proxy);
		write_ = std::bind(&T::HandleWrite, m_proxy);
		connect_ = std::bind(&T::HandleConnect, m_proxy);
		error_ = std::bind(&T::HandleError, m_proxy);
	}

	void HandleRead(){	if (read_){	read_();} }
	void HandleWrite() { if (write_) {	write_();} }
	void HandleConnect() { if (connect_) {	connect_();	} }
	void HandleError() { if (error_) {	error_();} }



};


/*!Initialize*/
static ISSLSession::SSLInit sslinit;