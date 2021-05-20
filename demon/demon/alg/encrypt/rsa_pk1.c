/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//#include "constant_time.h"

#include <stdio.h>
#include "bn.h"
#include "rsa_local.h"
#include "constant_time.h"
#include <time.h>


int RAND_bytes(unsigned char *out, size_t outlen)
{
	srand((unsigned)time(NULL));
	if (out == NULL || outlen == 0)
	{
		return 0;
	}
	for (size_t i = 0; i < outlen; i++)
	{
		out[i] = rand()%256;
	}
	return 1;
}

int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen)
{
    int j;
    unsigned char *p;

    if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		printf("RSA_padding_add_PKCS1_type_1 error!\n");
        return 0;
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 1;                 /* Private Key BT (Block Type) */

    /* pad out with 0xff data */
    j = tlen - 3 - flen;
    memset(p, 0xff, j);
    p += j;
    *(p++) = '\0';
    memcpy(p, from, (unsigned int)flen);
    return 1;
}

int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i, j;
    const unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < RSA_PKCS1_PADDING_SIZE)
        return -1;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {

			printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_INVALID_PADDING!\n");
            return -1;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 0x01)) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_BLOCK_TYPE_IS_NOT_01!\n");
        return -1;
    }

    /* scan over padding data */
    j = flen - 1;               /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) {       /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
			}
			else {
				printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_BAD_FIXED_HEADER_DECRYPT!\n");
                return -1;
            }
        }
        p++;
    }

	if (i == j) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_NULL_BEFORE_BLOCK_MISSING!\n");
        return -1;
    }

	if (i < 8) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_BAD_PAD_BYTE_COUNT!\n");
        return -1;
    }
    i++;                        /* Skip over the '\0' */
    j -= i;
	if (j > tlen) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 RSA_R_DATA_TOO_LARGE!\n");
        return -1;
    }
    memcpy(to, p, (unsigned int)j);

    return j;
}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen)
{
    int i, j;
    unsigned char *p;

	if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		printf("RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE!\n");
        return 0;
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 2;                 /* Public Key BT (Block Type) */

    /* pad out with non-zero random data */
    j = tlen - 3 - flen;

    if (RAND_bytes(p, j) <= 0)
        return 0;
    for (i = 0; i < j; i++) {
        if (*p == '\0')
            do {
                if (RAND_bytes(p, 1) <= 0)
                    return 0;
            } while (*p == '\0');
        p++;
    }

    *(p++) = '\0';

    memcpy(p, from, (unsigned int)flen);
    return 1;
}

int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i;
    /* |em| is the encoded message, zero-padded to exactly |num| bytes */
    unsigned char *em = NULL;
    unsigned int good, found_zero_byte, mask;
    int zero_index = 0, msg_index, mlen = -1;

    if (tlen <= 0 || flen <= 0)
        return -1;

    /*
     * PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography Standard",
     * section 7.2.2.
     */

	if (flen > num || num < RSA_PKCS1_PADDING_SIZE) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 RSA_R_PKCS_DECODING_ERROR!\n");
        return -1;
    }

    em = _malloc(num);
	if (em == NULL) {
		printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 ERR_R_MALLOC_FAILURE!\n");
        return -1;
    }
    /*
     * Caller is encouraged to pass zero-padded message created with
     * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
     * bounds, it's impossible to have an invariant memory access pattern
     * in case |from| was not zero-padded in advance.
     */
    for (from += flen, em += num, i = 0; i < num; i++) {
        mask = ~constant_time_is_zero(flen);
        flen -= 1 & mask;
        from -= 1 & mask;
        *--em = *from & mask;
    }

    good = constant_time_is_zero(em[0]);
    good &= constant_time_eq(em[1], 2);

    /* scan over padding data */
    found_zero_byte = 0;
    for (i = 2; i < num; i++) {
        unsigned int equals0 = constant_time_is_zero(em[i]);

        zero_index = constant_time_select_int(~found_zero_byte & equals0,
                                              i, zero_index);
        found_zero_byte |= equals0;
    }

    /*
     * PS must be at least 8 bytes long, and it starts two bytes into |em|.
     * If we never found a 0-byte, then |zero_index| is 0 and the check
     * also fails.
     */
    good &= constant_time_ge(zero_index, 2 + 8);

    /*
     * Skip the zero byte. This is incorrect if we never found a zero-byte
     * but in this case we also do not copy the message out.
     */
    msg_index = zero_index + 1;
    mlen = num - msg_index;

    /*
     * For good measure, do this check in constant time as well.
     */
    good &= constant_time_ge(tlen, mlen);

    /*
     * Move the result in-place by |num|-RSA_PKCS1_PADDING_SIZE-|mlen| bytes to the left.
     * Then if |good| move |mlen| bytes from |em|+RSA_PKCS1_PADDING_SIZE to |to|.
     * Otherwise leave |to| unchanged.
     * Copy the memory back in a way that does not reveal the size of
     * the data being copied via a timing side channel. This requires copying
     * parts of the buffer multiple times based on the bits set in the real
     * length. Clear bits do a non-copy with identical access pattern.
     * The loop below has overall complexity of O(N*log(N)).
     */
    tlen = constant_time_select_int(constant_time_lt(num - RSA_PKCS1_PADDING_SIZE, tlen),
                                    num - RSA_PKCS1_PADDING_SIZE, tlen);
    for (msg_index = 1; msg_index < num - RSA_PKCS1_PADDING_SIZE; msg_index <<= 1) {
        mask = ~constant_time_eq(msg_index & (num - RSA_PKCS1_PADDING_SIZE - mlen), 0);
        for (i = RSA_PKCS1_PADDING_SIZE; i < num - msg_index; i++)
            em[i] = constant_time_select_8(mask, em[i + msg_index], em[i]);
    }
    for (i = 0; i < tlen; i++) {
        mask = good & constant_time_lt(i, mlen);
        to[i] = constant_time_select_8(mask, em[i + RSA_PKCS1_PADDING_SIZE], to[i]);
    }

	_clear_free(em, num);
	printf("RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 RSA_R_PKCS_DECODING_ERROR!\n");
    //err_clear_last_constant_time(1 & good);

    return constant_time_select_int(good, mlen, -1);
}



int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
	const unsigned char *from, int flen,
	const unsigned char *param, int plen)
{
	return 1;
// 	return RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen,
// 		param, plen, NULL, NULL);
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
	const unsigned char *from, int flen,
	const unsigned char *param, int plen,
	const EVP_MD *md, const EVP_MD *mgf1md)
{
	return 0;
//	int rv = 0;
//	int i, emlen = tlen - 1;
//	unsigned char *db, *seed;
//	unsigned char *dbmask = NULL;
//	unsigned char seedmask[EVP_MAX_MD_SIZE];
//	int mdlen, dbmask_len = 0;
//
//	if (md == NULL)
//		md = EVP_sha1();
//	if (mgf1md == NULL)
//		mgf1md = md;
//
//	mdlen = EVP_MD_size(md);
//
//	if (flen > emlen - 2 * mdlen - 1) {
//		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
//			RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
//		return 0;
//	}
//
//	if (emlen < 2 * mdlen + 1) {
//		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
//			RSA_R_KEY_SIZE_TOO_SMALL);
//		return 0;
//	}
//
//	to[0] = 0;
//	seed = to + 1;
//	db = to + mdlen + 1;
//
//	if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
//		goto err;
//	memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
//	db[emlen - flen - mdlen - 1] = 0x01;
//	memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);
//	if (RAND_bytes(seed, mdlen) <= 0)
//		goto err;
//
//	dbmask_len = emlen - mdlen;
//	dbmask = OPENSSL_malloc(dbmask_len);
//	if (dbmask == NULL) {
//		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
//		goto err;
//	}
//
//	if (PKCS1_MGF1(dbmask, dbmask_len, seed, mdlen, mgf1md) < 0)
//		goto err;
//	for (i = 0; i < dbmask_len; i++)
//		db[i] ^= dbmask[i];
//
//	if (PKCS1_MGF1(seedmask, mdlen, db, dbmask_len, mgf1md) < 0)
//		goto err;
//	for (i = 0; i < mdlen; i++)
//		seed[i] ^= seedmask[i];
//	rv = 1;
//
//err:
//	_cleanse(seedmask, sizeof(seedmask));
//	OPENSSL_clear_free(dbmask, dbmask_len);
//	return rv;
}

int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
	const unsigned char *from, int flen, int num,
	const unsigned char *param, int plen)
{
// 	return RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, num,
// 		param, plen, NULL, NULL);
	return 1;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
	const unsigned char *from, int flen,
	int num, const unsigned char *param,
	int plen, const EVP_MD *md,
	const EVP_MD *mgf1md)
{
	return 0;
//	int i, dblen = 0, mlen = -1, one_index = 0, msg_index;
//	unsigned int good = 0, found_one_byte, mask;
//	const unsigned char *maskedseed, *maskeddb;
//	/*
//	* |em| is the encoded message, zero-padded to exactly |num| bytes: em =
//	* Y || maskedSeed || maskedDB
//	*/
//	unsigned char *db = NULL, *em = NULL, seed[EVP_MAX_MD_SIZE],
//		phash[EVP_MAX_MD_SIZE];
//	int mdlen;
//
//	if (md == NULL)
//		md = EVP_sha1();
//	if (mgf1md == NULL)
//		mgf1md = md;
//
//	mdlen = EVP_MD_size(md);
//
//	if (tlen <= 0 || flen <= 0)
//		return -1;
//	/*
//	* |num| is the length of the modulus; |flen| is the length of the
//	* encoded message. Therefore, for any |from| that was obtained by
//	* decrypting a ciphertext, we must have |flen| <= |num|. Similarly,
//	* |num| >= 2 * |mdlen| + 2 must hold for the modulus irrespective of
//	* the ciphertext, see PKCS #1 v2.2, section 7.1.2.
//	* This does not leak any side-channel information.
//	*/
//	if (num < flen || num < 2 * mdlen + 2) {
//		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
//			RSA_R_OAEP_DECODING_ERROR);
//		return -1;
//	}
//
//	dblen = num - mdlen - 1;
//	db = OPENSSL_malloc(dblen);
//	if (db == NULL) {
//		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
//		goto cleanup;
//	}
//
//	em = OPENSSL_malloc(num);
//	if (em == NULL) {
//		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
//			ERR_R_MALLOC_FAILURE);
//		goto cleanup;
//	}
//
//	/*
//	* Caller is encouraged to pass zero-padded message created with
//	* BN_bn2binpad. Trouble is that since we can't read out of |from|'s
//	* bounds, it's impossible to have an invariant memory access pattern
//	* in case |from| was not zero-padded in advance.
//	*/
//	for (from += flen, em += num, i = 0; i < num; i++) {
//		mask = ~constant_time_is_zero(flen);
//		flen -= 1 & mask;
//		from -= 1 & mask;
//		*--em = *from & mask;
//	}
//
//	/*
//	* The first byte must be zero, however we must not leak if this is
//	* true. See James H. Manger, "A Chosen Ciphertext  Attack on RSA
//	* Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
//	*/
//	good = constant_time_is_zero(em[0]);
//
//	maskedseed = em + 1;
//	maskeddb = em + 1 + mdlen;
//
//	if (PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md))
//		goto cleanup;
//	for (i = 0; i < mdlen; i++)
//		seed[i] ^= maskedseed[i];
//
//	if (PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md))
//		goto cleanup;
//	for (i = 0; i < dblen; i++)
//		db[i] ^= maskeddb[i];
//
//	if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL))
//		goto cleanup;
//
//	good &= constant_time_is_zero(CRYPTO_memcmp(db, phash, mdlen));
//
//	found_one_byte = 0;
//	for (i = mdlen; i < dblen; i++) {
//		/*
//		* Padding consists of a number of 0-bytes, followed by a 1.
//		*/
//		unsigned int equals1 = constant_time_eq(db[i], 1);
//		unsigned int equals0 = constant_time_is_zero(db[i]);
//		one_index = constant_time_select_int(~found_one_byte & equals1,
//			i, one_index);
//		found_one_byte |= equals1;
//		good &= (found_one_byte | equals0);
//	}
//
//	good &= found_one_byte;
//
//	/*
//	* At this point |good| is zero unless the plaintext was valid,
//	* so plaintext-awareness ensures timing side-channels are no longer a
//	* concern.
//	*/
//	msg_index = one_index + 1;
//	mlen = dblen - msg_index;
//
//	/*
//	* For good measure, do this check in constant time as well.
//	*/
//	good &= constant_time_ge(tlen, mlen);
//
//	/*
//	* Move the result in-place by |dblen|-|mdlen|-1-|mlen| bytes to the left.
//	* Then if |good| move |mlen| bytes from |db|+|mdlen|+1 to |to|.
//	* Otherwise leave |to| unchanged.
//	* Copy the memory back in a way that does not reveal the size of
//	* the data being copied via a timing side channel. This requires copying
//	* parts of the buffer multiple times based on the bits set in the real
//	* length. Clear bits do a non-copy with identical access pattern.
//	* The loop below has overall complexity of O(N*log(N)).
//	*/
//	tlen = constant_time_select_int(constant_time_lt(dblen - mdlen - 1, tlen),
//		dblen - mdlen - 1, tlen);
//	for (msg_index = 1; msg_index < dblen - mdlen - 1; msg_index <<= 1) {
//		mask = ~constant_time_eq(msg_index & (dblen - mdlen - 1 - mlen), 0);
//		for (i = mdlen + 1; i < dblen - msg_index; i++)
//			db[i] = constant_time_select_8(mask, db[i + msg_index], db[i]);
//	}
//	for (i = 0; i < tlen; i++) {
//		mask = good & constant_time_lt(i, mlen);
//		to[i] = constant_time_select_8(mask, db[i + mdlen + 1], to[i]);
//	}
//
//	/*
//	* To avoid chosen ciphertext attacks, the error message should not
//	* reveal which kind of decoding error happened.
//	*/
//	RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
//		RSA_R_OAEP_DECODING_ERROR);
//	err_clear_last_constant_time(1 & good);
//cleanup:
//	_cleanse(seed, sizeof(seed));
//	OPENSSL_clear_free(db, dblen);
//	OPENSSL_clear_free(em, num);
//
//	return constant_time_select_int(good, mlen, -1);
}

int PKCS1_MGF1(unsigned char *mask, long len,
	const unsigned char *seed, long seedlen, const EVP_MD *dgst)
{
	return 0;
// 	long i, outlen = 0;
// 	unsigned char cnt[4];
// 	EVP_MD_CTX *c = EVP_MD_CTX_new();
// 	unsigned char md[EVP_MAX_MD_SIZE];
// 	int mdlen;
// 	int rv = -1;
// 
// 	if (c == NULL)
// 		goto err;
// 	mdlen = EVP_MD_size(dgst);
// 	if (mdlen < 0)
// 		goto err;
// 	for (i = 0; outlen < len; i++) {
// 		cnt[0] = (unsigned char)((i >> 24) & 255);
// 		cnt[1] = (unsigned char)((i >> 16) & 255);
// 		cnt[2] = (unsigned char)((i >> 8)) & 255;
// 		cnt[3] = (unsigned char)(i & 255);
// 		if (!EVP_DigestInit_ex(c, dgst, NULL)
// 			|| !EVP_DigestUpdate(c, seed, seedlen)
// 			|| !EVP_DigestUpdate(c, cnt, 4))
// 			goto err;
// 		if (outlen + mdlen <= len) {
// 			if (!EVP_DigestFinal_ex(c, mask + outlen, NULL))
// 				goto err;
// 			outlen += mdlen;
// 		}
// 		else {
// 			if (!EVP_DigestFinal_ex(c, md, NULL))
// 				goto err;
// 			memcpy(mask + outlen, md, len - outlen);
// 			outlen = len;
// 		}
// 	}
// 	rv = 0;
// err:
// 	_cleanse(md, sizeof(md));
// 	EVP_MD_CTX_free(c);
// 	return rv;
}


int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *from, int flen)
{
//     int i, j;
//     unsigned char *p;
// 
//     if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
//         RSAerr(RSA_F_RSA_PADDING_ADD_SSLV23,
//                RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
//         return 0;
//     }
// 
//     p = (unsigned char *)to;
// 
//     *(p++) = 0;
//     *(p++) = 2;                 /* Public Key BT (Block Type) */
// 
//     /* pad out with non-zero random data */
//     j = tlen - 3 - 8 - flen;
// 
//     if (RAND_bytes(p, j) <= 0)
//         return 0;
//     for (i = 0; i < j; i++) {
//         if (*p == '\0')
//             do {
//                 if (RAND_bytes(p, 1) <= 0)
//                     return 0;
//             } while (*p == '\0');
//         p++;
//     }
// 
//     memset(p, 3, 8);
//     p += 8;
//     *(p++) = '\0';
// 
//     memcpy(p, from, (unsigned int)flen);
    return 1;
}

/*
 * Copy of RSA_padding_check_PKCS1_type_2 with a twist that rejects padding
 * if nul delimiter is not preceded by 8 consecutive 0x03 bytes. It also
 * preserves error code reporting for backward compatibility.
 */
int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *from, int flen, int num)
{
	return 0;
//     int i;
//     /* |em| is the encoded message, zero-padded to exactly |num| bytes */
//     unsigned char *em = NULL;
//     unsigned int good, found_zero_byte, mask, threes_in_row;
//     int zero_index = 0, msg_index, mlen = -1, err;
// 
//     if (tlen <= 0 || flen <= 0)
//         return -1;
// 
//     if (flen > num || num < RSA_PKCS1_PADDING_SIZE) {
//         RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_DATA_TOO_SMALL);
//         return -1;
//     }
// 
//     em = OPENSSL_malloc(num);
//     if (em == NULL) {
//         RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, ERR_R_MALLOC_FAILURE);
//         return -1;
//     }
//     /*
//      * Caller is encouraged to pass zero-padded message created with
//      * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
//      * bounds, it's impossible to have an invariant memory access pattern
//      * in case |from| was not zero-padded in advance.
//      */
//     for (from += flen, em += num, i = 0; i < num; i++) {
//         mask = ~constant_time_is_zero(flen);
//         flen -= 1 & mask;
//         from -= 1 & mask;
//         *--em = *from & mask;
//     }
// 
//     good = constant_time_is_zero(em[0]);
//     good &= constant_time_eq(em[1], 2);
//     err = constant_time_select_int(good, 0, RSA_R_BLOCK_TYPE_IS_NOT_02);
//     mask = ~good;
// 
//     /* scan over padding data */
//     found_zero_byte = 0;
//     threes_in_row = 0;
//     for (i = 2; i < num; i++) {
//         unsigned int equals0 = constant_time_is_zero(em[i]);
// 
//         zero_index = constant_time_select_int(~found_zero_byte & equals0,
//                                               i, zero_index);
//         found_zero_byte |= equals0;
// 
//         threes_in_row += 1 & ~found_zero_byte;
//         threes_in_row &= found_zero_byte | constant_time_eq(em[i], 3);
//     }
// 
//     /*
//      * PS must be at least 8 bytes long, and it starts two bytes into |em|.
//      * If we never found a 0-byte, then |zero_index| is 0 and the check
//      * also fails.
//      */
//     good &= constant_time_ge(zero_index, 2 + 8);
//     err = constant_time_select_int(mask | good, err,
//                                    RSA_R_NULL_BEFORE_BLOCK_MISSING);
//     mask = ~good;
// 
//     good &= constant_time_ge(threes_in_row, 8);
//     err = constant_time_select_int(mask | good, err,
//                                    RSA_R_SSLV3_ROLLBACK_ATTACK);
//     mask = ~good;
// 
//     /*
//      * Skip the zero byte. This is incorrect if we never found a zero-byte
//      * but in this case we also do not copy the message out.
//      */
//     msg_index = zero_index + 1;
//     mlen = num - msg_index;
// 
//     /*
//      * For good measure, do this check in constant time as well.
//      */
//     good &= constant_time_ge(tlen, mlen);
//     err = constant_time_select_int(mask | good, err, RSA_R_DATA_TOO_LARGE);
// 
//     /*
//      * Move the result in-place by |num|-RSA_PKCS1_PADDING_SIZE-|mlen| bytes to the left.
//      * Then if |good| move |mlen| bytes from |em|+RSA_PKCS1_PADDING_SIZE to |to|.
//      * Otherwise leave |to| unchanged.
//      * Copy the memory back in a way that does not reveal the size of
//      * the data being copied via a timing side channel. This requires copying
//      * parts of the buffer multiple times based on the bits set in the real
//      * length. Clear bits do a non-copy with identical access pattern.
//      * The loop below has overall complexity of O(N*log(N)).
//      */
//     tlen = constant_time_select_int(constant_time_lt(num - RSA_PKCS1_PADDING_SIZE, tlen),
//                                     num - RSA_PKCS1_PADDING_SIZE, tlen);
//     for (msg_index = 1; msg_index < num - RSA_PKCS1_PADDING_SIZE; msg_index <<= 1) {
//         mask = ~constant_time_eq(msg_index & (num - RSA_PKCS1_PADDING_SIZE - mlen), 0);
//         for (i = RSA_PKCS1_PADDING_SIZE; i < num - msg_index; i++)
//             em[i] = constant_time_select_8(mask, em[i + msg_index], em[i]);
//     }
//     for (i = 0; i < tlen; i++) {
//         mask = good & constant_time_lt(i, mlen);
//         to[i] = constant_time_select_8(mask, em[i + RSA_PKCS1_PADDING_SIZE], to[i]);
//     }
// 
//     OPENSSL_clear_free(em, num);
//     RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, err);
//     err_clear_last_constant_time(1 & good);
// 
//     return constant_time_select_int(good, mlen, -1);
}

/*! none padding ###########################################################*/
int RSA_padding_add_none(unsigned char *to, int tlen,
	const unsigned char *from, int flen)
{
	if (flen > tlen) {
		RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return 0;
	}

	if (flen < tlen) {
		RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
		return 0;
	}

	memcpy(to, from, (unsigned int)flen);
	return 1;
}

int RSA_padding_check_none(unsigned char *to, int tlen,
	const unsigned char *from, int flen, int num)
{

	if (flen > tlen) {
		RSAerr(RSA_F_RSA_PADDING_CHECK_NONE, RSA_R_DATA_TOO_LARGE);
		return -1;
	}

	memset(to, 0, tlen - flen);
	memcpy(to + tlen - flen, from, flen);
	return tlen;
}


/*!x931*/
int RSA_padding_add_X931(unsigned char *to, int tlen,
	const unsigned char *from, int flen)
{
// 	int j;
// 	unsigned char *p;
// 
// 	/*
// 	* Absolute minimum amount of padding is 1 header nibble, 1 padding
// 	* nibble and 2 trailer bytes: but 1 hash if is already in 'from'.
// 	*/
// 
// 	j = tlen - flen - 2;
// 
// 	if (j < 0) {
// 		RSAerr(RSA_F_RSA_PADDING_ADD_X931, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
// 		return -1;
// 	}
// 
// 	p = (unsigned char *)to;
// 
// 	/* If no padding start and end nibbles are in one byte */
// 	if (j == 0) {
// 		*p++ = 0x6A;
// 	}
// 	else {
// 		*p++ = 0x6B;
// 		if (j > 1) {
// 			memset(p, 0xBB, j - 1);
// 			p += j - 1;
// 		}
// 		*p++ = 0xBA;
// 	}
// 	memcpy(p, from, (unsigned int)flen);
// 	p += flen;
// 	*p = 0xCC;
	return 1;
}

int RSA_padding_check_X931(unsigned char *to, int tlen,
	const unsigned char *from, int flen, int num)
{
	return 0;
// 	int i = 0, j;
// 	const unsigned char *p;
// 
// 	p = from;
// 	if ((num != flen) || ((*p != 0x6A) && (*p != 0x6B))) {
// 		RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_HEADER);
// 		return -1;
// 	}
// 
// 	if (*p++ == 0x6B) {
// 		j = flen - 3;
// 		for (i = 0; i < j; i++) {
// 			unsigned char c = *p++;
// 			if (c == 0xBA)
// 				break;
// 			if (c != 0xBB) {
// 				RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_PADDING);
// 				return -1;
// 			}
// 		}
// 
// 		j -= i;
// 
// 		if (i == 0) {
// 			RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_PADDING);
// 			return -1;
// 		}
// 
// 	}
// 	else {
// 		j = flen - 2;
// 	}
// 
// 	if (p[j] != 0xCC) {
// 		RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_TRAILER);
// 		return -1;
// 	}
// 
// 	memcpy(to, p, (unsigned int)j);
// 
// 	return j;
}

/* Translate between X931 hash ids and NIDs */

int RSA_X931_hash_id(int nid)
{
	// 	switch (nid) {
	// 	case NID_sha1:
	// 		return 0x33;
	// 
	// 	case NID_sha256:
	// 		return 0x34;
	// 
	// 	case NID_sha384:
	// 		return 0x36;
	// 
	// 	case NID_sha512:
	// 		return 0x35;
	// 
	// 	}
	return -1;
}
