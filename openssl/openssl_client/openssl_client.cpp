// openssl.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<tchar.h>
#include<WinSock2.h>
#include<WS2tcpip.h>
#include<iostream>
#include<openssl\ssl.h>
#include<openssl\err.h>

#pragma comment(lib, "ws2_32")



#define PORT 8080
#define MAXBUF 1024

void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		printf("数字证书信息:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("证书: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("颁发者: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("无证书信息！\n");
}

int main(int argc, char **argv)
{
	WSADATA wsadData;
	WSAStartup(MAKEWORD(2, 2), &wsadData);

	int sockfd, len;
	struct sockaddr_in dest;
	char buffer[MAXBUF + 1];
	SSL_CTX *ctx;
	SSL *ssl;

	/* SSL 库初始化，参看 ssl-server.c 代码 */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	/* 创建一个 socket 用于 tcp 通信 */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket");
		exit(errno);
	}
	printf("socket created\n");

	/* 初始化服务器端（对方）的地址和端口信息 */
	memset(&dest,0x00, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
	//dest.sin_addr.s_addr = inet_addr("127.0.0.1");

	/* 连接服务器 */
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
		printf("connect error:%d\n", GetLastError());
	}

	/* 基于 ctx 产生一个新的 SSL */
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	/* 建立 SSL 连接 */
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}

	/* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */
	memset(buffer, 0x00, MAXBUF + 1);
	/* 接收服务器来的消息 */
	len = SSL_read(ssl, buffer, MAXBUF);
	if (len > 0)
		printf("接收消息成功:'%s'，共%d个字节的数据\n",
			buffer, len);
	else {
		printf
		("消息接收失败！错误代码是%d\n",errno);
		goto finish;
	}
	memset(buffer,0x00 ,MAXBUF + 1);
	memcpy(buffer, "from client->server",strlen("from client->server"));
	/* 发消息给服务器 */
	len = SSL_write(ssl, buffer, strlen(buffer));
	if (len < 0)
		printf
		("消息'%s'发送失败！错误代码是%d\n",buffer, errno);
	else
		printf("消息'%s'发送成功，共发送了%d个字节！\n",
			buffer, len);

finish:
	/* 关闭连接 */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}