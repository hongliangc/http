/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include "bn.h"

/* The types RSA and RSA_METHOD are defined in ossl_typ.h */

# ifndef OPENSSL_RSA_MAX_MODULUS_BITS
#  define OPENSSL_RSA_MAX_MODULUS_BITS   16384
# endif

# define OPENSSL_RSA_FIPS_MIN_MODULUS_BITS 1024

# ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
#  define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
# endif
# ifndef OPENSSL_RSA_MAX_PUBEXP_BITS

/* exponent limit enforced for "large" modulus only */
#  define OPENSSL_RSA_MAX_PUBEXP_BITS    64
# endif

# define RSA_3   0x3L
# define RSA_F4  0x10001L

/* based on RFC 8017 appendix A.1.2 */
# define RSA_ASN1_VERSION_DEFAULT        0
# define RSA_ASN1_VERSION_MULTI          1

# define RSA_DEFAULT_PRIME_NUM           2

# define RSA_METHOD_FLAG_NO_CHECK        0x0001/* don't check pub/private
                                                * match */

# define RSA_FLAG_CACHE_PUBLIC           0x0002
# define RSA_FLAG_CACHE_PRIVATE          0x0004
# define RSA_FLAG_BLINDING               0x0008
# define RSA_FLAG_THREAD_SAFE            0x0010
/*
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag
 * bn_mod_exp gets called when private key components are absent.
 */
# define RSA_FLAG_EXT_PKEY               0x0020

/*
 * new with 0.9.6j and 0.9.7b; the built-in
 * RSA implementation now uses blinding by
 * default (ignoring RSA_FLAG_BLINDING),
 * but other engines might not need it
 */
# define RSA_FLAG_NO_BLINDING            0x0080



/* Salt length matches digest */
# define RSA_PSS_SALTLEN_DIGEST -1
/* Verify only: auto detect salt length */
# define RSA_PSS_SALTLEN_AUTO   -2
/* Set salt length to maximum possible */
# define RSA_PSS_SALTLEN_MAX    -3
/* Old compatible max salt length for sign only */
# define RSA_PSS_SALTLEN_MAX_SIGN    -2



# define RSA_PKCS1_PADDING       1
# define RSA_SSLV23_PADDING      2
# define RSA_NO_PADDING          3
# define RSA_PKCS1_OAEP_PADDING  4
# define RSA_X931_PADDING        5
/* EVP_PKEY_ only */
# define RSA_PKCS1_PSS_PADDING   6

# define RSA_PKCS1_PADDING_SIZE  11




# define RSA_FLAG_FIPS_METHOD                    0x0400

/*
* If this flag is set the operations normally disabled in FIPS mode are
* permitted it is then the applications responsibility to ensure that the
* usage is compliant.
*/

# define RSA_FLAG_NON_FIPS_ALLOW                 0x0400
/*
* Application has decided PRNG is good enough to generate a key: don't
* check.
*/
# define RSA_FLAG_CHECKED                        0x0800

	RSA *RSA_new_method();
	void RSA_free(RSA *r);


	int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
		const unsigned char *f, int fl);
	int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
		const unsigned char *f, int fl,
		int rsa_len);
	int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
		const unsigned char *f, int fl);
	int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
		const unsigned char *f, int fl,
		int rsa_len);
	int PKCS1_MGF1(unsigned char *mask, long len, const unsigned char *seed,
		long seedlen, const EVP_MD *dgst);
	int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
		const unsigned char *f, int fl,
		const unsigned char *p, int pl);
	int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
		const unsigned char *f, int fl, int rsa_len,
		const unsigned char *p, int pl);

	int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
		const unsigned char *f, int fl);
	int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
		const unsigned char *f, int fl, int rsa_len);

	int RSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *f,
		int fl);
	int RSA_padding_check_none(unsigned char *to, int tlen,
		const unsigned char *f, int fl, int rsa_len);
	int RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f,
		int fl);
	int RSA_padding_check_X931(unsigned char *to, int tlen,
		const unsigned char *f, int fl, int rsa_len);

#endif
