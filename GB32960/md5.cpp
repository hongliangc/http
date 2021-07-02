/**
* Copyright (C) 2011-2012，武汉海微科技有限公司
* All rights reserved.
*
* 文件名称：kmd5.cpp
* 摘    要：MD5算法的实现
* 版    本：1.0.0
* 修改日期：2007-5-30
* 作    者：
* 修改历史：
* [修改序列][修改日期][修改者][修改内容]
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

#pragma warning(disable:4996)

/* Padding */
static unsigned char MD5_PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* MD5_F, MD5_G and MD5_H are basic MD5 functions: selection, majority, parity */
#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#ifndef ROTATE_LEFT
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#endif

/* MD5_FF, MD5_GG, MD5_HH, and MD5_II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define MD5_FF(a, b, c, d, x, s, ac) {(a) += MD5_F ((b), (c), (d)) + (x) + (unsigned int)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_GG(a, b, c, d, x, s, ac) {(a) += MD5_G ((b), (c), (d)) + (x) + (unsigned int)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_HH(a, b, c, d, x, s, ac) {(a) += MD5_H ((b), (c), (d)) + (x) + (unsigned int)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define MD5_II(a, b, c, d, x, s, ac) {(a) += MD5_I ((b), (c), (d)) + (x) + (unsigned int)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }

/* Constants for transformation */
#define MD5_S11 7  /* Round 1 */
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5  /* Round 2 */
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4  /* Round 3 */
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6  /* Round 4 */
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

/* Basic MD5 step. MD5_Transform buf based on in */
void KMD5::MD5_Transform(unsigned int *buf, unsigned int *in)
{
	unsigned int a = buf[0], b = buf[1], c = buf[2], d = buf[3];

	/* Round 1 */
	MD5_FF(a, b, c, d, in[0], MD5_S11, (unsigned int)3614090360u); /* 1 */
	MD5_FF(d, a, b, c, in[1], MD5_S12, (unsigned int)3905402710u); /* 2 */
	MD5_FF(c, d, a, b, in[2], MD5_S13, (unsigned int)606105819u); /* 3 */
	MD5_FF(b, c, d, a, in[3], MD5_S14, (unsigned int)3250441966u); /* 4 */
	MD5_FF(a, b, c, d, in[4], MD5_S11, (unsigned int)4118548399u); /* 5 */
	MD5_FF(d, a, b, c, in[5], MD5_S12, (unsigned int)1200080426u); /* 6 */
	MD5_FF(c, d, a, b, in[6], MD5_S13, (unsigned int)2821735955u); /* 7 */
	MD5_FF(b, c, d, a, in[7], MD5_S14, (unsigned int)4249261313u); /* 8 */
	MD5_FF(a, b, c, d, in[8], MD5_S11, (unsigned int)1770035416u); /* 9 */
	MD5_FF(d, a, b, c, in[9], MD5_S12, (unsigned int)2336552879u); /* 10 */
	MD5_FF(c, d, a, b, in[10], MD5_S13, (unsigned int)4294925233u); /* 11 */
	MD5_FF(b, c, d, a, in[11], MD5_S14, (unsigned int)2304563134u); /* 12 */
	MD5_FF(a, b, c, d, in[12], MD5_S11, (unsigned int)1804603682u); /* 13 */
	MD5_FF(d, a, b, c, in[13], MD5_S12, (unsigned int)4254626195u); /* 14 */
	MD5_FF(c, d, a, b, in[14], MD5_S13, (unsigned int)2792965006u); /* 15 */
	MD5_FF(b, c, d, a, in[15], MD5_S14, (unsigned int)1236535329u); /* 16 */

																 /* Round 2 */
	MD5_GG(a, b, c, d, in[1], MD5_S21, (unsigned int)4129170786u); /* 17 */
	MD5_GG(d, a, b, c, in[6], MD5_S22, (unsigned int)3225465664u); /* 18 */
	MD5_GG(c, d, a, b, in[11], MD5_S23, (unsigned int)643717713u); /* 19 */
	MD5_GG(b, c, d, a, in[0], MD5_S24, (unsigned int)3921069994u); /* 20 */
	MD5_GG(a, b, c, d, in[5], MD5_S21, (unsigned int)3593408605u); /* 21 */
	MD5_GG(d, a, b, c, in[10], MD5_S22, (unsigned int)38016083u); /* 22 */
	MD5_GG(c, d, a, b, in[15], MD5_S23, (unsigned int)3634488961u); /* 23 */
	MD5_GG(b, c, d, a, in[4], MD5_S24, (unsigned int)3889429448u); /* 24 */
	MD5_GG(a, b, c, d, in[9], MD5_S21, (unsigned int)568446438u); /* 25 */
	MD5_GG(d, a, b, c, in[14], MD5_S22, (unsigned int)3275163606u); /* 26 */
	MD5_GG(c, d, a, b, in[3], MD5_S23, (unsigned int)4107603335u); /* 27 */
	MD5_GG(b, c, d, a, in[8], MD5_S24, (unsigned int)1163531501u); /* 28 */
	MD5_GG(a, b, c, d, in[13], MD5_S21, (unsigned int)2850285829u); /* 29 */
	MD5_GG(d, a, b, c, in[2], MD5_S22, (unsigned int)4243563512u); /* 30 */
	MD5_GG(c, d, a, b, in[7], MD5_S23, (unsigned int)1735328473u); /* 31 */
	MD5_GG(b, c, d, a, in[12], MD5_S24, (unsigned int)2368359562u); /* 32 */

																 /* Round 3 */
	MD5_HH(a, b, c, d, in[5], MD5_S31, (unsigned int)4294588738u); /* 33 */
	MD5_HH(d, a, b, c, in[8], MD5_S32, (unsigned int)2272392833u); /* 34 */
	MD5_HH(c, d, a, b, in[11], MD5_S33, (unsigned int)1839030562u); /* 35 */
	MD5_HH(b, c, d, a, in[14], MD5_S34, (unsigned int)4259657740u); /* 36 */
	MD5_HH(a, b, c, d, in[1], MD5_S31, (unsigned int)2763975236u); /* 37 */
	MD5_HH(d, a, b, c, in[4], MD5_S32, (unsigned int)1272893353u); /* 38 */
	MD5_HH(c, d, a, b, in[7], MD5_S33, (unsigned int)4139469664u); /* 39 */
	MD5_HH(b, c, d, a, in[10], MD5_S34, (unsigned int)3200236656u); /* 40 */
	MD5_HH(a, b, c, d, in[13], MD5_S31, (unsigned int)681279174u); /* 41 */
	MD5_HH(d, a, b, c, in[0], MD5_S32, (unsigned int)3936430074u); /* 42 */
	MD5_HH(c, d, a, b, in[3], MD5_S33, (unsigned int)3572445317u); /* 43 */
	MD5_HH(b, c, d, a, in[6], MD5_S34, (unsigned int)76029189u); /* 44 */
	MD5_HH(a, b, c, d, in[9], MD5_S31, (unsigned int)3654602809u); /* 45 */
	MD5_HH(d, a, b, c, in[12], MD5_S32, (unsigned int)3873151461u); /* 46 */
	MD5_HH(c, d, a, b, in[15], MD5_S33, (unsigned int)530742520u); /* 47 */
	MD5_HH(b, c, d, a, in[2], MD5_S34, (unsigned int)3299628645u); /* 48 */

																/* Round 4 */
	MD5_II(a, b, c, d, in[0], MD5_S41, (unsigned int)4096336452u); /* 49 */
	MD5_II(d, a, b, c, in[7], MD5_S42, (unsigned int)1126891415u); /* 50 */
	MD5_II(c, d, a, b, in[14], MD5_S43, (unsigned int)2878612391u); /* 51 */
	MD5_II(b, c, d, a, in[5], MD5_S44, (unsigned int)4237533241u); /* 52 */
	MD5_II(a, b, c, d, in[12], MD5_S41, (unsigned int)1700485571u); /* 53 */
	MD5_II(d, a, b, c, in[3], MD5_S42, (unsigned int)2399980690u); /* 54 */
	MD5_II(c, d, a, b, in[10], MD5_S43, (unsigned int)4293915773u); /* 55 */
	MD5_II(b, c, d, a, in[1], MD5_S44, (unsigned int)2240044497u); /* 56 */
	MD5_II(a, b, c, d, in[8], MD5_S41, (unsigned int)1873313359u); /* 57 */
	MD5_II(d, a, b, c, in[15], MD5_S42, (unsigned int)4264355552u); /* 58 */
	MD5_II(c, d, a, b, in[6], MD5_S43, (unsigned int)2734768916u); /* 59 */
	MD5_II(b, c, d, a, in[13], MD5_S44, (unsigned int)1309151649u); /* 60 */
	MD5_II(a, b, c, d, in[4], MD5_S41, (unsigned int)4149444226u); /* 61 */
	MD5_II(d, a, b, c, in[11], MD5_S42, (unsigned int)3174756917u); /* 62 */
	MD5_II(c, d, a, b, in[2], MD5_S43, (unsigned int)718787259u); /* 63 */
	MD5_II(b, c, d, a, in[9], MD5_S44, (unsigned int)3951481745u); /* 64 */

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

// Set pseudoRandomNumber to zero for RFC MD5 implementation
void KMD5::MD5Init(MD5_CTX *mdContext, unsigned long pseudoRandomNumber)
{
	mdContext->i[0] = mdContext->i[1] = (unsigned int)0;

	/* Load magic initialization constants */
	mdContext->buf[0] = (unsigned int)0x67452301 + (pseudoRandomNumber * 11);
	mdContext->buf[1] = (unsigned int)0xefcdab89 + (pseudoRandomNumber * 71);
	mdContext->buf[2] = (unsigned int)0x98badcfe + (pseudoRandomNumber * 37);
	mdContext->buf[3] = (unsigned int)0x10325476 + (pseudoRandomNumber * 97);
}

void KMD5::MD5Update(MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen)
{
	unsigned int in[16];
	int mdi = 0;
	unsigned int i = 0, ii = 0;

	/* Compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((mdContext->i[0] + ((unsigned int)inLen << 3)) < mdContext->i[0])
		mdContext->i[1]++;
	mdContext->i[0] += ((unsigned int)inLen << 3);
	mdContext->i[1] += ((unsigned int)inLen >> 29);

	//int iCell = inLen / 100;

	while (inLen--)
	{
		/* Add new character to buffer, increment mdi */
		mdContext->in[mdi++] = *inBuf++;

		/* Transform if necessary */
		if (mdi == 0x40)
		{
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] = (((unsigned int)mdContext->in[ii + 3]) << 24) |
				(((unsigned int)mdContext->in[ii + 2]) << 16) |
				(((unsigned int)mdContext->in[ii + 1]) << 8) |
				((unsigned int)mdContext->in[ii]);

			MD5_Transform(mdContext->buf, in);
			mdi = 0;
		}
	}
}

void KMD5::MD5Final(MD5_CTX *mdContext)
{
	unsigned int in[16];
	int mdi = 0;
	unsigned int i = 0, ii = 0, padLen = 0;

	/* Save number of bits */
	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];

	/* Compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	/* Pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5Update(mdContext, MD5_PADDING, padLen);

	/* Append length in bits and transform */
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((unsigned int)mdContext->in[ii + 3]) << 24) |
		(((unsigned int)mdContext->in[ii + 2]) << 16) |
		(((unsigned int)mdContext->in[ii + 1]) << 8) |
		((unsigned int)mdContext->in[ii]);
	MD5_Transform(mdContext->buf, in);

	/* Store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4)
	{
		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii + 1] = (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii + 2] = (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii + 3] = (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}

/***********************************************************************
* 函数功能：计算缓冲区数据的MD5值, 返回16 hw_int8S值
* 参    数：
* 		buffer [in]：缓冲区的数据
* 		bufferLen [in]：缓冲区的大小
*		md5Value [out]：MD5值,
* 返 回 值：0表示成功
***********************************************************************/
int KMD5::MD5Hash(unsigned char * buffer, int bufferLen, unsigned char md5Value[16])
{
	m_nPrgCount = 0;
	m_bFinal = false;
	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context, buffer, bufferLen);
	m_bFinal = true;
	MD5Final(&context);
	memcpy(md5Value, context.digest, 16);
	return 0;
}

/***********************************************************************
* 函数功能：把hw_int8[16] 转换成16进制32位字符串
* 参    数：
* 		bytes [in]：hw_int8 型MD5值
* 		str [out]：6进制32位字符串MD5值, 如 3C4CAEF2CA3C89047846FA4EBF062A5F
* 返 回 值：0表示成功
***********************************************************************/
int KMD5::Byte16ToChar32(unsigned char bytes[16], char str[33])
{
	memset(str, 0, 33);
	sprintf(str, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

	return 0;
}

/***********************************************************************
* 函数功能：把hw_int8[16] 转换成16进制16位字符串(从第4个字节开始取8个字节)
* 参    数：
* 		bytes [in]：hw_int8 型MD5值
* 		str [out]：6进制32位字符串MD5值, 如 3C4CAEF2CA3C89047846FA4EBF062A5F
* 返 回 值：0表示成功
***********************************************************************/
int KMD5::Byte16ToChar16(unsigned char bytes[16], char str[17])
{
	memset(str, 0, 17);
	sprintf(str, "%02X%02X%02X%02X%02X%02X%02X%02X",
		bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]);

	return 0;
}
int KMD5::MD5HashFile(const char * path, unsigned char md5Value[16])
{
	int len = 8 * 1024;
	unsigned char *buf = new unsigned char[len];
	FILE * fd = 0;
	m_nPrgCount = 0;
	m_bFinal = false;
	fd = fopen(path, "rb+");
	if (NULL != fd)
	{
		MD5_CTX context;
		MD5Init(&context);
		while (!feof(fd))
		{
			memset(buf, 0x00, len);
			int rlen = fread(buf, 1, len, fd);
			if (rlen > 0)
			{
				MD5Update(&context, buf, rlen);
			}
			else
			{
				break;
			}
		}
		m_bFinal = true;
		MD5Final(&context);
		memcpy(md5Value, context.digest, 16);
		fclose(fd);
		fd = 0;
		return 0;
	}
	else
	{
		return -1;
	}
}