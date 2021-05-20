#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#define ossl_inline
#define BNerr(a,b)
#define RSAerr(a,b) printf("%s, %s\n", #a,#b)
//#define RSAerr(a,b) print("%s, %s\n", a,b)

#  define BN_ULONG        unsigned long long
#  define BN_BYTES        8


#  define BN_BITS4        32
#  define BN_MASK2        (0xffffffffffffffffLL)
#  define BN_MASK2l       (0xffffffffL)
#  define BN_MASK2h       (0xffffffff00000000LL)
#  define BN_MASK2h1      (0xffffffff80000000LL)
#  define BN_DEC_CONV     (10000000000000000000ULL)
#  define BN_DEC_NUM      19
#  define BN_DEC_FMT1     "%llu"
#  define BN_DEC_FMT2     "%019llu"
// 
// struct bignum_st {
// 	BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
// 								* chunks. */
// 	int top;                    /* Index of last used d +1. */
// 								/* The next are internal book keeping for bn_expand. */
// 	int dmax;                   /* Size of the d array. */
// 	int neg;                    /* one if the number is negative */
// 	int flags;
// };

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;


typedef struct evp_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct rsa_meth_st;
typedef struct rsa_meth_st RSA_METHOD;

struct rsa_st {
	/*
	* The first parameter is used to pickup errors where this is passed
	* instead of an EVP_PKEY, it is set to 0
	*/
	int pad;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	const RSA_METHOD *meth;

	/* Used to cache montgomery values */
	BN_MONT_CTX *_method_mod_n;
	BN_MONT_CTX *_method_mod_p;
	BN_MONT_CTX *_method_mod_q;
};
typedef struct rsa_st RSA;

struct rsa_meth_st {
	char *name;
	int(*rsa_pub_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	int(*rsa_pub_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	int(*rsa_priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	int(*rsa_priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	/* Can be null */
	int(*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
	/* Can be null */
	int(*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
	/* called at new */
	int(*init) (RSA *rsa);
	/* called at free */
	int(*finish) (RSA *rsa);
	/* RSA_METHOD_FLAG_* things */
	int flags;
	/* may be needed! */
	char *app_data;
	/*
	* New sign and verify functions: some libraries don't allow arbitrary
	* data to be signed/verified: this allows them to be used. Note: for
	* this to work the RSA_public_decrypt() and RSA_private_encrypt() should
	* *NOT* be used RSA_sign(), RSA_verify() should be used instead.
	*/
	int(*rsa_sign) (int type,
		const unsigned char *m, unsigned int m_length,
		unsigned char *sigret, unsigned int *siglen,
		const RSA *rsa);
	int(*rsa_verify) (int dtype, const unsigned char *m,
		unsigned int m_length, const unsigned char *sigbuf,
		unsigned int siglen, const RSA *rsa);
	/*
	* If this callback is NULL, the builtin software RSA key-gen will be
	* used. This is for behavioural compatibility whilst the code gets
	* rewired, but one day it would be nice to assume there are no such
	* things as "builtin software" implementations.
	*/
	int(*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
	int(*rsa_multi_prime_keygen) (RSA *rsa, int bits, int primes,
		BIGNUM *e, BN_GENCB *cb);
};



/*
* BN function codes.
*/
# define BN_F_BNRAND                                      127
# define BN_F_BNRAND_RANGE                                138
# define BN_F_BN_BLINDING_CONVERT_EX                      100
# define BN_F_BN_BLINDING_CREATE_PARAM                    128
# define BN_F_BN_BLINDING_INVERT_EX                       101
# define BN_F_BN_BLINDING_NEW                             102
# define BN_F_BN_BLINDING_UPDATE                          103
# define BN_F_BN_BN2DEC                                   104
# define BN_F_BN_BN2HEX                                   105
# define BN_F_BN_COMPUTE_WNAF                             142
# define BN_F_BN_CTX_GET                                  116
# define BN_F_BN_CTX_NEW                                  106
# define BN_F_BN_CTX_START                                129
# define BN_F_BN_DIV                                      107
# define BN_F_BN_DIV_RECP                                 130
# define BN_F_BN_EXP                                      123
# define BN_F_BN_EXPAND_INTERNAL                          120
# define BN_F_BN_GENCB_NEW                                143
# define BN_F_BN_GENERATE_DSA_NONCE                       140
# define BN_F_BN_GENERATE_PRIME_EX                        141
# define BN_F_BN_GF2M_MOD                                 131
# define BN_F_BN_GF2M_MOD_EXP                             132
# define BN_F_BN_GF2M_MOD_MUL                             133
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD                      134
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR                  135
# define BN_F_BN_GF2M_MOD_SQR                             136
# define BN_F_BN_GF2M_MOD_SQRT                            137
# define BN_F_BN_LSHIFT                                   145
# define BN_F_BN_MOD_EXP2_MONT                            118
# define BN_F_BN_MOD_EXP_MONT                             109
# define BN_F_BN_MOD_EXP_MONT_CONSTTIME                   124
# define BN_F_BN_MOD_EXP_MONT_WORD                        117
# define BN_F_BN_MOD_EXP_RECP                             125
# define BN_F_BN_MOD_EXP_SIMPLE                           126
# define BN_F_BN_MOD_INVERSE                              110
# define BN_F_BN_MOD_INVERSE_NO_BRANCH                    139
# define BN_F_BN_MOD_LSHIFT_QUICK                         119
# define BN_F_BN_MOD_SQRT                                 121
# define BN_F_BN_MONT_CTX_NEW                             149
# define BN_F_BN_MPI2BN                                   112
# define BN_F_BN_NEW                                      113
# define BN_F_BN_POOL_GET                                 147
# define BN_F_BN_RAND                                     114
# define BN_F_BN_RAND_RANGE                               122
# define BN_F_BN_RECP_CTX_NEW                             150
# define BN_F_BN_RSHIFT                                   146
# define BN_F_BN_SET_WORDS                                144
# define BN_F_BN_STACK_PUSH                               148
# define BN_F_BN_USUB                                     115

/*
* BN reason codes.
*/
# define BN_R_ARG2_LT_ARG3                                100
# define BN_R_BAD_RECIPROCAL                              101
# define BN_R_BIGNUM_TOO_LONG                             114
# define BN_R_BITS_TOO_SMALL                              118
# define BN_R_CALLED_WITH_EVEN_MODULUS                    102
# define BN_R_DIV_BY_ZERO                                 103
# define BN_R_ENCODING_ERROR                              104
# define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA                105
# define BN_R_INPUT_NOT_REDUCED                           110
# define BN_R_INVALID_LENGTH                              106
# define BN_R_INVALID_RANGE                               115
# define BN_R_INVALID_SHIFT                               119
# define BN_R_NOT_A_SQUARE                                111
# define BN_R_NOT_INITIALIZED                             107
# define BN_R_NO_INVERSE                                  108
# define BN_R_NO_SOLUTION                                 116
# define BN_R_PRIVATE_KEY_TOO_LARGE                       117
# define BN_R_P_IS_NOT_PRIME                              112
# define BN_R_TOO_MANY_ITERATIONS                         113
# define BN_R_TOO_MANY_TEMPORARY_VARIABLES                109


/*!memory*/
void _cleanse(void *ptr, size_t len);
void _free(void *str);

void _clear_free(void *str, size_t num);
void *_malloc(size_t num);
void *_zalloc(size_t num);
void *_realloc(void *str, size_t num);
void *_clear_realloc(void *str, size_t old_len, size_t num);

void *_memdup_(const void *data, size_t siz);
char *_strdup_(const char *str);
char *_strndup_(const char *str, size_t s);


size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size);
size_t OPENSSL_strnlen(const char *str, size_t maxlen);
size_t OPENSSL_strlcat(char *dst, const char *src, size_t size);
int OPENSSL_hexchar2int(unsigned char c);


# define OPENSSL_malloc(num) \
        _malloc(num)
# define OPENSSL_zalloc(num) \
        _zalloc(num)
# define OPENSSL_realloc(addr, num) \
        _realloc(addr, num)
# define OPENSSL_clear_realloc(addr, old_num, num) \
        _clear_realloc(addr, old_num, num)
# define OPENSSL_clear_free(addr, num) \
        _clear_free(addr, num)
# define OPENSSL_free(addr) \
        _free(addr)

# define OPENSSL_memdup(str, s) \
        _memdup_((str), s)
# define OPENSSL_strdup(str) \
        _strdup_(str)
# define OPENSSL_strndup(str, n) \
        _strndup_(str, n)
# define OPENSSL_secure_malloc(num) \
        _malloc(num)
# define OPENSSL_secure_zalloc(num) \
        _zalloc(num)
# define OPENSSL_secure_free(addr) \
        _free(addr)
# define OPENSSL_secure_clear_free(addr, num) \
        _clear_free(addr, num)
# define OPENSSL_secure_actual_size(ptr) \
        _secure_actual_size(ptr)

/*!EVP*/
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;


# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEX_SIZE(type)          (sizeof(type)*2)


/*! AES */
int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);

void OPENSSL_cleanse(void *ptr, size_t len);