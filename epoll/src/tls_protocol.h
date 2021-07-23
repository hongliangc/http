#pragma once
#include "utility.h"
extern "C" {
#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"
}
#include <errno.h>
#include <sstream>
#include <iostream>
#include <thread>
#include <assert.h>

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
#include <signal.h>

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

namespace tls {

#ifndef _WIN32

#define MaxClient 1024
	class Epoll
	{
	public:
		Epoll()	{
			m_fd = -1;
			m_status = false;
		}
		/*!初始化*/
		bool Initialize(){
			if (m_status){
				return true;
			}
			m_fd = epoll_create(MaxClient);
			if (m_fd == -1)	{
				_LOG(logTypeCommon, "Epoll epoll_create failed err:%d", Errno_);
				return false;
			}
			m_status = true;
			return true;
		}

		void Destroy(){
			if (m_fd != -1) {
				close(m_fd);
			}
		}

		int32_t Insert(int32_t fd, struct epoll_event &ev){
			epoll_ctl(m_fd, EPOLL_CTL_ADD, fd, &ev);
			return 0;
		}

		int32_t Modify(int32_t fd, struct epoll_event &ev){
			epoll_ctl(m_fd, EPOLL_CTL_ADD, fd, &ev);
			return 0;
		}

		int32_t Remove(int32_t fd){
			struct epoll_event ev;
			epoll_ctl(m_fd, EPOLL_CTL_DEL, fd, &ev);
			return 0;
		}

		int32_t WaitEvent(struct epoll_event *EventSet, int count, uint32_t milliseconds)
		{
			return epoll_wait(m_fd, EventSet, count, milliseconds);			
		}
	public:
		bool m_status;
		int32_t m_fd;
	};
#endif
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


	struct SslDeleter {
		void operator()(SSL *_p) {
			SSL_shutdown(_p);
			SSL_free(_p);
		}

		void operator()(SSL_CTX *_p) {
			SSL_CTX_free(_p);
		}
	};
	using UniqueSslPtr = std::unique_ptr<SSL, SslDeleter>;
	using UniqueCtxPtr = std::unique_ptr<SSL_CTX, SslDeleter>;


	class TaskQueue
	{
	public:
		using callback_ = std::function<void()>;
	public:
		TaskQueue() = default;
		virtual ~TaskQueue() = default;
		virtual int32_t Enqueue(const callback_& cb) = 0;
		virtual int32_t Shutdown() = 0;
	};


#ifndef _THREAD_POOL_COUNT
	// #define _THREAD_POOL_COUNT   \
		//   ((std::max)(1u, std::thread::hardware_concurrency() - 1))
#define	_THREAD_POOL_COUNT 10
#endif
	class ThreadPool :public TaskQueue
	{
	public:
		explicit ThreadPool(unsigned int num = _THREAD_POOL_COUNT) :m_status(true) {
			for (; num > 0; num--) {
				m_threads.emplace_back(worker(this, num));
			}
		}
		ThreadPool(const ThreadPool&) = delete;

		int32_t Enqueue(const callback_& cb) override {
			std::unique_lock<std::mutex> lock(m_mutex);
			m_jobs.emplace_back(cb);
			//_LOG(logTypeCommon, "worker Enqueue mutex:0x%0x size:%d", &m_mutex, m_jobs.size());
			m_cond.notify_one();
			return 0;
		}
		int32_t Shutdown() override {
			{
				std::unique_lock<std::mutex> lock(m_mutex);
				m_status = false;
			}
			m_cond.notify_all();
			for (auto &e : m_threads)
			{
				e.join();
			}
			return 0;
		}
	private:
		struct worker {
			explicit worker(ThreadPool *pool, int id) :m_pool(pool), m_id(id) {}
			void operator()() {
				//std::stringstream ss;
				//ss << std::this_thread::get_id();
				//uint64_t id = std::stoull(ss.str());
				do {
					TaskQueue::callback_ fn;
					{
						std::unique_lock<std::mutex> lock(m_pool->m_mutex);
						m_pool->m_cond.wait(lock, [&] { return (m_pool->m_jobs.size() != 0) || m_pool->m_status == false; });
						if (m_pool->m_status == false && m_pool->m_jobs.size() == 0) {
							_LOG(logTypeCommon, "worker id:%d quit", m_id);
							break;
						}
						auto own_lock = lock.owns_lock();
						if (own_lock == false)
						{
							_LOG(logTypeCommon, "worker id:%d not obtain mutex size:%d", m_id, m_pool->m_jobs.size());
							continue;
						}
						//_LOG(logTypeCommon, "worker id:%d ready to call cb,m_mutex:0x%0x, size:%d,own_lock:%d", m_id, &m_pool->m_mutex, m_pool->m_jobs.size(), own_lock);
						fn = std::move(m_pool->m_jobs.front());
						m_pool->m_jobs.pop_front();
						//_LOG(logTypeCommon, "worker id:%d fininsh, size:%d", m_id, m_pool->m_jobs.size());
					}
					assert(true == static_cast<bool>(fn));
					fn();
				} while (true);
			}
		public:
			int m_id;
			ThreadPool *m_pool;
		};
	private:
		bool m_status;
		std::mutex m_mutex;
		std::condition_variable m_cond;
		std::vector<std::thread> m_threads;
		std::list<callback_> m_jobs;
		friend struct worker;
	};



	template<typename Proxy>
	class Channel :public std::enable_shared_from_this<Channel<Proxy>>
	{
	public:
		/*!注册读写事件,隔离应用层和底层读写接口*/
		std::function<int(Channel<Proxy>*, char*, int)> m_read;
		std::function<int(Channel<Proxy>*, char*, int)> m_write;

		Proxy m_proxy;
		socket_ m_sock;
		std::shared_ptr<SSL> m_ssl;
		bool m_status;
	public:
		std::weak_ptr<Channel<Proxy>> weak_self() {
			return std::weak_ptr<Channel<Proxy>>(this->shared_from_this());
		}

		bool Initialize()
		{
			//static_assert(std::is_member_function_pointer<decltype(&Proxy::Register)>::value, "T::Register is not a member function.");
			m_proxy.Register(
				std::bind(&Channel<Proxy>::HandleRead, this, std::placeholders::_1, std::placeholders::_2),
				std::bind(&Channel<Proxy>::HandleWrite, this, std::placeholders::_1, std::placeholders::_2));
			m_status = true;
			return true;
		}

		void Destroy()
		{
			m_status = false;
		}

		explicit Channel(
			std::function<int(Channel<Proxy>*, char*, int)> read,
			std::function<int(Channel<Proxy>*, char*, int)> write) :
			m_read(read), m_write(write), m_sock(INVALID_SOCKET), m_status(false){
		}

		~Channel()
		{
			_LOG(logTypeCommon, "~Channel() addres:0x%0x, fd:%d", this, m_sock);
			if (m_sock != INVALID_SOCKET)
			{
				closesocket(m_sock);
				m_sock = INVALID_SOCKET;
			}
			m_read = nullptr;
			m_write = nullptr;
			Destroy();
		}

		bool TryAgain()
		{
			int err = Errno_;
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

		/*!读写回调给代理*/
		int HandleRead(char* buffer, int len) {
			if (m_read && m_status) { return m_read(this, buffer, len); }
			else { return -1; }
		}
		int HandleWrite(char* buffer, int len) {
			if (m_write && m_status) { return m_write(this, buffer, len); }
			else { return -1; }
		}

		/*!客户端事件处理*/
		void OnMessage() {
			if (m_status == false){
				return;
			}
			if (m_read && m_write) {
				char buff[8*1024];
				int total = 0;
				do
				{
					int received = HandleRead(buff, 8*1024);
					if (received > 0)
					{
						total += received;
					}
					else if (TryAgain() == true)
					{
						break;
					}
					else
					{
						OnError(Errno_);
						_LOG(logTypeCommon, "Channle OnMessage error:%d", Errno_);
						break;
					}

				} while (1);
				if (total > 0)
				{
					m_proxy.OnMessage(m_sock, buff, total);
				}
			}
			else {
				_LOG(logTypeCommon, "Channel OnMessage read or write is null!");
			}
		}

		void OnError(int err) {
			m_proxy.OnError(err);
		}

	};


	class ISSLSession
	{
	public:
		class SSLInit {
		public:
			SSLInit() {
#ifndef _WIN32
				signal(SIGPIPE, SIG_IGN);
#endif
				SSL_library_init();
				OpenSSL_add_all_algorithms();
				SSL_load_error_strings();
			}
		};
	public:
		using ListData = std::list<std::shared_ptr<StruSslData>>;
		using DataCb = std::function<int(char*, int, int)>;
		using Fn_init = std::function<bool(socket_ sock, const struct addrinfo &ai)>;
	public:
		ISSLSession() :m_sock(INVALID_SOCKET), m_status(false) {}
		virtual ~ISSLSession() {}
		virtual socket_ CreateSocket(std::string host, int port, Fn_init fn)
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
		
		bool TryAgain()
		{
			int err = Errno_;
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

	protected:
		socket_ m_sock;
		bool m_status;
		UniqueCtxPtr m_ctx;
	};


#define NON_BLOCKING_ 
	class CSSLClient :public ISSLSession
	{
	public:
		CSSLClient() :ISSLSession() {}
		~CSSLClient() {
			_LOG(logTypeCommon, "~CSSLClient is called addr:0x%0x", this);
			Destroy();
		}

		bool SendData(char* data, int len)
		{
			if (m_status == false)
			{
				return false;
			}
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

		virtual void OnRecv(char* buffer, int len) {}

		virtual void OnError(int err) {}

		void RunTask()
		{
#ifdef NON_BLOCKING_ 
			set_nonblock(m_sock, true);
#endif
			try
			{
				while (m_status)
				{
					do
					{
						int received = 0;
						fd_set fds;
						struct timeval timeout;

						char buffer[1024*8] = { '\0' };
						/*!需要设置为非阻塞,同线程可以发送数据*/
						received = SSL_read(m_ssl.get(), buffer, sizeof(buffer));
						if (received > 0)
						{
							//_LOG(logTypeCommon, "CSSLClient SSL_read len:%d", received);
							OnRecv(buffer, received);
						}
						else
						{
							int ssl_err = SSL_get_error(m_ssl.get(), received);
							switch (ssl_err)
							{
							case SSL_ERROR_ZERO_RETURN:
							case SSL_ERROR_SSL:
								// peer disconnected...
								_LOG(logTypeCommon, "CSSLClient SSL_read error:%d,ssl_err:%d", Errno_, ssl_err);
								OnError(Errno_);
								return;
							case SSL_ERROR_WANT_READ:
								// no data available right now, wait a few seconds in case new data arrives...
								if (SSL_get_rfd(m_ssl.get()) == m_sock)
								{
									FD_ZERO(&fds);
									FD_SET(m_sock, &fds);
									timeout.tv_sec = 0;
									timeout.tv_usec = 500 * 1000;
									int ret = select(m_sock + 1, &fds, NULL, NULL, &timeout);
									if (ret > 0)
										continue;
									if (ret == 0) {
									}
									else {
										_LOG(logTypeCommon, "CSSLClient RunTask select error:%d", Errno_);
										OnError(Errno_);
										return;
									}
									break;
								}
							}
						}
					} while (0);

					if (m_listData.size() > 0)
					{
						std::unique_lock<std::mutex> lock(m_mutex);
						//_LOG(logTypeCommon, "CSSLClient SSL_write m_listData size:%d", m_listData.size());
						for (auto iter = m_listData.begin(); iter != m_listData.end(); )
						{
							StruSslData *data = (*iter).get();
							unsigned int offset = 0;
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
									int ssl_err = SSL_get_error(m_ssl.get(), ret);
									if (TryAgain() == true && ssl_err != SSL_ERROR_ZERO_RETURN && ssl_err != SSL_ERROR_SSL)
									{
										_LOG(logTypeCommon, "CSSLClient SSL_write failed! try_count:%d,ssl_err:%d", try_count++, ssl_err);
										std::this_thread::sleep_for(std::chrono::seconds(1));
										continue;
									}
									else
									{
										OnError(Errno_);
										_LOG(logTypeCommon, "CSSLClient SSL_write failed! erron:%d, ssl_err:%d", Errno_, ssl_err);
										return;
									}
								}
							} while (offset < data->m_len && try_count < 3);
							if (offset == data->m_len)
							{
								iter = m_listData.erase(iter);
								_LOG(logTypeCommon, "CSSLClient SSL_write fd:%d, success len:%d", m_sock, offset);
							}
							else
							{
								iter++;
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
				ret = SSL_connect(ssl);
				if (ret == 1) {
					break;
				}

				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(m_sock, &fds);
				int decodedError = SSL_get_error(ssl, ret);

				timeval tv;
				tv.tv_sec = seconds;
				tv.tv_usec = 0;
				if (decodedError == SSL_ERROR_WANT_READ) {
					int result = select(m_sock + 1, &fds, NULL, NULL, &tv);
					if (result <= 0) {
						_LOG(logTypeCommon, "NonBlockingConnect SSL_ERROR_WANT_READ error:%d", Errno_);

						decodedError = SSL_get_error(ssl, decodedError);
						ERR_print_errors_fp(stderr);
						_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(decodedError, NULL));
						return ret;
					}
				}
				else if (decodedError == SSL_ERROR_WANT_WRITE) {
					int result = select(m_sock + 1, NULL, &fds, NULL, &tv);
					if (result <= 0) {
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
			}
			return ret;
		}
		
		bool Initialize(std::string host, uint32_t port)
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
							int ret = select(static_cast<int>(sock + 1), &fdsr, &fdsw, &fdse, &tv);
							if ((ret > 0) &&	(FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw))) {
								int error = 0;
								socklen_t len = sizeof(error);
								return getsockopt(sock, SOL_SOCKET, SO_ERROR,
									reinterpret_cast<char *>(&error), &len) >= 0 &&
									!error;
							}
							else if(ret == 0) {
								_LOG(logTypeCommon, "connect select timeout!");
							}
							else{
								_LOG(logTypeCommon, "connect select error:%d!", Errno_);
							}
							return false;
						};
						if (Connection_Error(Errno_) || !Check(sock, 10, 0))
						{
							_LOG(logTypeCommon, "CSSLClient connect failed! erron:%d", Errno_);
							return false;
						}
					}
#ifndef NON_BLOCKING_
					set_nonblock(sock, false);
#endif
					return true;
				};
				m_sock = CreateSocket(host, port, init);
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
				m_ssl = std::shared_ptr<SSL>(SSL_new(m_ctx.get()), SslDeleter{});
				if (m_ssl == nullptr)
				{
					ERR_print_errors_fp(stderr);
					_LOG(logTypeCommon, "SSL_new failed");
					closesocket(m_sock);
					return false;
				}
				SSL_set_fd(m_ssl.get(), m_sock);
#ifdef NON_BLOCKING_
				auto status = NonBlockingConnect(m_ssl.get(), 5);
#else
				auto status = SSL_connect(m_ssl.get());
#endif
				if (status <= 0) {
					status = SSL_get_error(m_ssl.get(), status);
					ERR_print_errors_fp(stderr);
					closesocket(m_sock);
					_LOG(logTypeCommon, "SSL_connect failed errinfo:%s ", ERR_error_string(status, NULL));
					return false;
				}
				else {
					/*!获取检测结果*/
					status = SSL_get_verify_result(m_ssl.get());
					if (status != X509_V_OK) {
						closesocket(m_sock);
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
					_LOG(logTypeCommon, "SSL session conneect fd:%d", m_sock);
				}

				m_status = true;
				m_thread = std::make_unique<std::thread>([this]() { RunTask(); });
			}
			catch (const std::exception& e)
			{
				_LOG(logTypeCommon, "CSSLClient Initialize catch exception:%s", e.what());
			}
			return  true;
		}


		void Destroy()
		{
			try
			{
				_LOG(logTypeCommon, "CSSLClient Destroy is called  addr:0x%0x, fd:%d", this, m_sock);
				m_status = false;
				m_listData.clear();
				if (m_thread)
				{
					if (m_thread->joinable())
					{
						m_thread->join();
					}
				}

				if (m_sock != INVALID_SOCKET)
				{
					closesocket(m_sock);
					m_sock = INVALID_SOCKET;
				}

				if (m_ssl)
				{
					m_ssl.reset();
					m_ssl = nullptr;
				}
			}
			catch (const std::exception& e)
			{
				_LOG(logTypeCommon, "CSSLClient Destroy catch exception:%s", e.what());
			}
		}
	public:
		std::mutex m_mutex;
		ListData m_listData;
		std::shared_ptr<SSL> m_ssl;
		std::unique_ptr<std::thread> m_thread;
	};




	template<typename T>
	class CSSLServer :public ISSLSession
	{
		using CallBack = std::function<void()>;
	private:
		std::unique_ptr<std::thread> m_thread;
#ifndef _WIN32
		Epoll m_epoll;
#endif
		std::mutex m_ClientMutex;
		std::map<socket_, std::shared_ptr<T>> m_ClientMap;
	public:
		CSSLServer() :ISSLSession() {}
		~CSSLServer() {
			_LOG(logTypeCommon, "~CSSLServer is called address:0x%0x",this);
			Destroy();
		}

		void RunTask()

		{
			//set_nonblock(m_sock, true);
			try
			{
				std::unique_ptr<TaskQueue> task_queue(new ThreadPool());
				while (m_status)
				{
#ifdef _WIN32
					fd_set fdsr;
					FD_ZERO(&fdsr);
					timeval tv;
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					socket_ sock = m_sock;
					FD_SET(m_sock, &fdsr);
					for (auto element: m_ClientMap)	{
						FD_SET(element.first, &fdsr);
						if (element.first > sock){
							sock = element.first;
						}
					}


					int ret = select(static_cast<int>(sock + 1), &fdsr, nullptr, nullptr, &tv);
					if (ret > 0) {
						if (FD_ISSET(m_sock, &fdsr))
						{
							HandleConn();
						}

						{
							std::unique_lock<std::mutex> lock(m_ClientMutex);
							for (auto iter = m_ClientMap.begin(); iter != m_ClientMap.end();)
							{
								int err = Errno_;
								int ssl_err = SSL_get_error(iter->second->m_ssl.get(), -1);
								if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_ZERO_RETURN)
								{
									_LOG(logTypeCommon, "CSSLServer RunTask fd:%d closed, err:%d, ssl_err:%d", iter->first, err, ssl_err);
									iter->second->Destroy();
									iter->second->OnError(Errno_);
									iter = m_ClientMap.erase(iter);
									continue;

								}
								else if (FD_ISSET(iter->first, &fdsr))
								{
#if 1
									static int count = 0;
									if (++count % 100 == 0)
									{
										_LOG(logTypeCommon, "TaskQueue Enqueue count:%d", count);
									}

 									task_queue->Enqueue([self = iter->second->weak_self()]() {
										//_LOG(logTypeCommon, "TaskQueue before use_count:%d", self.use_count());
										if (auto instan = self.lock())
										{											
											instan->OnMessage();
											//_LOG(logTypeCommon, "TaskQueue after use_count:%d", self.use_count());
										}
 										//_LOG(logTypeCommon, "TaskQueue OUT channel:0x%0x, fd:%d", self, self->m_sock);
									});
#else
									char buff[8 * 1024];
									int len = SSL_read(iter->second->m_ssl.get(), buff, sizeof(buff));
									if (len <= 0)
									{
										int err = Errno_;
										int ssl_err = SSL_get_error(iter->second->m_ssl.get(), len);
										_LOG(logTypeCommon, "CSSLServer SSL_read fd:%d, err:%d, ssl_err:%d", iter->first, err, ssl_err);
										if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
										{
											iter = m_ClientMap.erase(iter);
											continue;
										}
									}
									_LOG(logTypeCommon, "Server SSL_read total len:%d, fd:%d", len, iter->first);
#endif

								}
								iter++;
							}
						}
					}
					else if (ret == 0) {
						//_LOG(logTypeCommon, "connect select timeout!");
					}
					else {
						_LOG(logTypeCommon, "connect select error:%d!", Errno_);
					}
#else

					struct epoll_event events[MaxClient];
					memset(events, 0, MaxClient * sizeof(struct epoll_event));
					int ready_num = m_epoll.WaitEvent(events, MaxClient, 1000);
					//_LOG(logTypeCommon, "CSSLServer trigger Events num:%d", ready_num);
					if (ready_num > 0) {
						for (int i = 0; i < ready_num; ++i) {
							int fd = events[i].data.fd;
							if (events[i].events & EPOLLRDHUP) {
								std::unique_lock<std::mutex> lock(m_ClientMutex);
								_LOG(logTypeCommon, "CSSLServer socket:%d closed", fd);
								auto iter = m_ClientMap.find(fd);
								if (iter != m_ClientMap.end())
								{
									iter->second->Destroy();
									iter->second.get()->OnError(Errno_);
									m_ClientMap.erase(iter);
								}
								m_epoll.Remove(fd);
								continue;
							}
							if (events[i].events & EPOLLIN) {
								if (fd == m_sock)
								{
									HandleConn();
								}
								else
								{
									{
										std::unique_lock<std::mutex> lock(m_ClientMutex);
										auto iter = m_ClientMap.find(fd);
										if (iter == m_ClientMap.end())
										{
											_LOG(logTypeCommon, "CSSLServer HandleWrite not find ssl");
											continue;
										}


										task_queue->Enqueue([self = iter->second->weak_self()]() {
											//_LOG(logTypeCommon, "TaskQueue before use_count:%d", self.use_count());
											if (auto instan = self.lock())
											{
												instan->OnMessage();
												//_LOG(logTypeCommon, "TaskQueue after use_count:%d", self.use_count());
											}
										});
									}
								}
							}
						}
					}
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

		bool Initialize(std::string host, uint32_t port)
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
			m_sock = CreateSocket(host, port, init);
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

#ifndef _WIN32
			if (!m_epoll.Initialize())
			{
				_LOG(logTypeCommon, "CSSLServer Epoll initialize failed!");
				closesocket(m_sock);
				return false;
			}

			struct epoll_event ev;
			ev.events = EPOLLIN /*| EPOLLET */ | EPOLLRDHUP;
			ev.data.fd = m_sock;

			m_epoll.Insert(m_sock, ev);
#endif
			m_status = true;
			m_thread = std::make_unique<std::thread>([this]() { RunTask(); });
			return  true;
		}

		int HandleRead(T *proxy, char *buffer, int buflen)
		{
			if (proxy == NULL || buffer == NULL || buflen == 0)
			{
				_LOG(logTypeCommon, "CSSLServer HandleRead param error!");
				return -1;
			}

			if (m_ClientMap.find(proxy->m_sock) == m_ClientMap.end())
			{
				return -1;
			}
			/*!需要设置为非阻塞,否则会阻塞*/
			int len = SSL_read(proxy->m_ssl.get(), buffer, buflen);
			if (len <= 0/* && TryAgain() != true*/)
			{
				int err = Errno_;
				int ssl_err = SSL_get_error(proxy->m_ssl.get(), len);
				if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_ZERO_RETURN || (ssl_err == SSL_ERROR_SYSCALL && err == 0) || (TryAgain() != true))
				{
					_LOG(logTypeCommon, "CSSLServer HandleRead fd:%d, err:%d, ssl_err:%d", proxy->m_sock, err, ssl_err);
					std::unique_lock<std::mutex> lock(m_ClientMutex);
					auto iter = m_ClientMap.find(proxy->m_sock);
					if (iter != m_ClientMap.end())
					{
						iter->second->Destroy();
						iter->second->OnError(err);
						m_ClientMap.erase(iter);
					}
				}
				return -1;
			}
			return len;
		}


		int HandleWrite(T *proxy, char *buffer, int buflen)
		{
			if (proxy == NULL || buffer == NULL || buflen == 0)
			{
				_LOG(logTypeCommon, "CSSLServer HandleRead param error!");
				return 0;
			}

			if (m_ClientMap.find(proxy->m_sock) == m_ClientMap.end())
			{
				return -1;
			}
			/*!需要设置为非阻塞,否则会阻塞*/
			int len = SSL_write(proxy->m_ssl.get(), buffer, buflen);
			if (len <= 0 /*&& TryAgain() != true*/)
			{
				int err = Errno_;
				int ssl_err = SSL_get_error(proxy->m_ssl.get(), len);
				if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_ZERO_RETURN || (ssl_err == SSL_ERROR_SYSCALL && err == 0) || (TryAgain() != true))
				{
					_LOG(logTypeCommon, "CSSLServer HandleWrite fd:%d, err:%d, ssl_err:%d", proxy->m_sock, err, ssl_err);
					std::unique_lock<std::mutex> lock(m_ClientMutex);
					auto iter = m_ClientMap.find(proxy->m_sock);
					if (iter != m_ClientMap.end())
					{
						iter->second->Destroy();
						iter->second->OnError(err);
						m_ClientMap.erase(iter);
					}
				}
				return -1;
			}
			return len;
		}

		void HandleConn()
		{
			socklen_t len = sizeof(struct sockaddr_in);
			struct sockaddr_in remote_addr;
			/* 等待客户端连上来 */
			auto sock = accept(m_sock, (struct sockaddr *) &remote_addr, &len);
			if (sock == -1) {
				_LOG(logTypeCommon, "CSSLServer accept failed err:%d", Errno_);
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}

			char ip[32] = { 0 };
			inet_ntop(AF_INET, &remote_addr.sin_addr, ip, sizeof(ip));
			//_LOG(logTypeCommon, "CSSLServer client %s:%d, socket %d\n", ip, ntohs(remote_addr.sin_port), sock);

			auto ssl = std::shared_ptr<SSL>(SSL_new(m_ctx.get()), SslDeleter{});
// 			auto ssl = std::shared_ptr<SSL>(SSL_new(m_ctx.get()), [](SSL *_p) {
// 				SSL_shutdown(_p);
// 				SSL_free(_p);
// 			});
			if (ssl == nullptr)
			{
				ERR_print_errors_fp(stderr);
				_LOG(logTypeCommon, "CSSLServer SSL_new failed");
				closesocket(sock);
				return;
			}
			if (SSL_set_fd(ssl.get(), sock) == 0)
			{
				ERR_print_errors_fp(stderr);
				_LOG(logTypeCommon, "CSSLServer SSL_set_fd failed");
				closesocket(sock);
				return;
			}
			/* 建立SSL连接 */
			if (SSL_accept(ssl.get()) == -1) {
				_LOG(logTypeCommon, "CSSLServer SSL_accept failed err:%d", Errno_);
				closesocket(sock);
				return;
			}

			/*!添加新连接*/
			std::shared_ptr<T> channel = std::make_shared<T>(
			std::bind(&tls::CSSLServer<T>::HandleRead,this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
			std::bind(&tls::CSSLServer<T>::HandleWrite, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

			if (channel->Initialize() == false)
			{
				_LOG(logTypeCommon, "CSSLServer channel initialize failed!");
				closesocket(sock);
				return;
			}
			channel->m_ssl = ssl;
			channel->m_sock = sock;

			{
				std::unique_lock<std::mutex> lock(m_ClientMutex);
				auto iter = m_ClientMap.find(sock);
				if (iter != m_ClientMap.end())
				{
					m_ClientMap.erase(iter);
				}
				m_ClientMap[sock] = std::move(channel);
			}
			set_nonblock(sock, true);

#ifndef _WIN32
			struct epoll_event ev;
			ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
			//ev.data.ptr = reinterpret_cast<void *>(&data);
			ev.data.fd = sock;

			m_epoll.Insert(sock, ev);
#endif
			_LOG(logTypeCommon, "CSSLServer client connecting success tuple:(%s:%d), socket %d, client count:%d\n", ip, ntohs(remote_addr.sin_port), sock, m_ClientMap.size());
		}

		void Destroy()
		{
			_LOG(logTypeCommon, "CSSLServer Destroy is called  addr:0x%0x, fd:%d", this, m_sock);
			m_status = false;
			{
				std::unique_lock<std::mutex> lock(m_ClientMutex);
				m_ClientMap.clear();
			}
			if (m_thread)
			{
				if (m_thread->joinable())
				{
					m_thread->join();
				}
			}

			if (m_sock != INVALID_SOCKET)
			{
				closesocket(m_sock);
				m_sock = INVALID_SOCKET;
			}
		}
	};

	/*!Initialize*/
	static ISSLSession::SSLInit sslinit;

}