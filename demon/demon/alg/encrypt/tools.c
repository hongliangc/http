#pragma once

#include"tools.h"

void _cleanse(void *ptr, size_t len)
{
	memset(ptr, 0, len);
}

void _free(void *str)
{
	if (str != NULL)
	{
		free(str);
	}
}

void _clear_free(void *str, size_t num)
{
	if (str == NULL)
		return;
	if (num)
		_cleanse(str, num);
	_free(str);
}


void *_malloc(size_t num)
{
	void *ret = NULL;
	ret = malloc(num);

	return ret;
}

void *_zalloc(size_t num)
{
	void *ret = _malloc(num);

	if (ret != NULL)
		memset(ret, 0, num);
	return ret;
}


void *_realloc(void *str, size_t num)
{
	if (num == 0) {
		_free(str);
		return NULL;
	}

	return realloc(str, num);

}

void *_clear_realloc(void *str, size_t old_len, size_t num)
{
	void *ret = NULL;

	if (str == NULL)
		return _malloc(num);

	if (num == 0) {
		_clear_free(str, old_len);
		return NULL;
	}

	/* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
	if (num < old_len) {
		_cleanse((char*)str + num, old_len - num);
		return str;
	}

	ret = _malloc(num);
	if (ret != NULL) {
		memcpy(ret, str, old_len);
		_clear_free(str, old_len);
	}
	return ret;
}



int OPENSSL_memcmp(const void *v1, const void *v2, size_t n)
{
	const unsigned char *c1 = v1, *c2 = v2;
	int ret = 0;

	while (n && (ret = *c1 - *c2) == 0)
		n--, c1++, c2++;

	return ret;
}

char *_strdup_(const char *str)
{
	char *ret;

	if (str == NULL)
		return NULL;
	ret = _malloc(strlen(str) + 1);
	if (ret != NULL)
		strcpy(ret, str);
	return ret;
}

char *_strndup_(const char *str, size_t s)
{
	size_t maxlen;
	char *ret;

	if (str == NULL)
		return NULL;

	maxlen = OPENSSL_strnlen(str, s);

	ret = _malloc(maxlen + 1);
	if (ret) {
		memcpy(ret, str, maxlen);
		ret[maxlen] = '\0';
	}
	return ret;
}

void *_memdup_(const void *data, size_t siz)
{
	void *ret;

	if (data == NULL || siz >= INT_MAX)
		return NULL;

	ret = _malloc(siz);
	if (ret == NULL) {
		return NULL;
	}
	return memcpy(ret, data, siz);
}

size_t OPENSSL_strnlen(const char *str, size_t maxlen)
{
	const char *p;

	for (p = str; maxlen-- != 0 && *p != '\0'; ++p);

	return p - str;
}

size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size)
{
	size_t l = 0;
	for (; size > 1 && *src; size--) {
		*dst++ = *src++;
		l++;
	}
	if (size)
		*dst = '\0';
	return l + strlen(src);
}

size_t OPENSSL_strlcat(char *dst, const char *src, size_t size)
{
	size_t l = 0;
	for (; size > 0 && *dst; size--, dst++)
		l++;
	return l + OPENSSL_strlcpy(dst, src, size);
}

int OPENSSL_hexchar2int(unsigned char c)
{

	switch (c) {
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a': case 'A':
		return 0x0A;
	case 'b': case 'B':
		return 0x0B;
	case 'c': case 'C':
		return 0x0C;
	case 'd': case 'D':
		return 0x0D;
	case 'e': case 'E':
		return 0x0E;
	case 'f': case 'F':
		return 0x0F;
	}
	return -1;
}

/*
* Give a string of hex digits convert to a buffer
*/
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len)
{
	unsigned char *hexbuf, *q;
	unsigned char ch, cl;
	int chi, cli;
	const unsigned char *p;
	size_t s;

	s = strlen(str);
	if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
		return NULL;
	}
	for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
		ch = *p++;
		if (ch == ':')
			continue;
		cl = *p++;
		if (!cl) {
			OPENSSL_free(hexbuf);
			return NULL;
		}
		cli = OPENSSL_hexchar2int(cl);
		chi = OPENSSL_hexchar2int(ch);
		if (cli < 0 || chi < 0) {
			OPENSSL_free(hexbuf);
			return NULL;
		}
		*q++ = (unsigned char)((chi << 4) | cli);
	}

	if (len)
		*len = q - hexbuf;
	return hexbuf;
}

/*
* Given a buffer of length 'len' return a OPENSSL_malloc'ed string with its
* hex representation @@@ (Contents of buffer are always kept in ASCII, also
* on EBCDIC machines)
*/
char *OPENSSL_buf2hexstr(const unsigned char *buffer, long len)
{
	static const char hexdig[] = "0123456789ABCDEF";
	char *tmp, *q;
	const unsigned char *p;
	int i;

	if (len == 0)
	{
		return OPENSSL_zalloc(1);
	}

	if ((tmp = OPENSSL_malloc(len * 3)) == NULL) {
		return NULL;
	}
	q = tmp;
	for (i = 0, p = buffer; i < len; i++, p++) {
		*q++ = hexdig[(*p >> 4) & 0xf];
		*q++ = hexdig[*p & 0xf];
		*q++ = ':';
	}
	q[-1] = 0;

	return tmp;
}

size_t _secure_actual_size(void *ptr)
{
	return 0;
}


int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
{
	size_t i;
	const volatile unsigned char *a = in_a;
	const volatile unsigned char *b = in_b;
	unsigned char x = 0;

	for (i = 0; i < len; i++)
		x |= a[i] ^ b[i];

	return x;
}

void OPENSSL_cleanse(void *ptr, size_t len)
{
	memset(ptr, 0, len);
}