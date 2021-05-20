/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//#include <openssl/evp.h>

# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32

# define PKCS5_SALT_LEN                  8
/* Default PKCS#5 iteration count */
# define PKCS5_DEFAULT_ITER              2048


typedef struct evp_cipher_st EVP_CIPHER;

struct evp_md_ctx_st {
	const EVP_MD *digest;
	unsigned long flags;
	void *md_data;
	/* Public key context for sign/verify */
	EVP_PKEY_CTX *pctx;
	/* Update function: usually copied from EVP_MD */
	int(*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */;

struct evp_cipher_ctx_st {
	const EVP_CIPHER *cipher;
	int encrypt;                /* encrypt or decrypt */
	int buf_len;                /* number we have left */
	unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
	unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
	unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
	int num;                    /* used by cfb/ofb/ctr mode */
								/* FIXME: Should this even exist? It appears unused */
	void *app_data;             /* application stuff */
	int key_len;                /* May change for variable length cipher */
	unsigned long flags;        /* Various flags */
	void *cipher_data;          /* per EVP data */
	int final_used;
	int block_mask;
	unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */;



struct evp_Encode_Ctx_st {
	/* number saved in a partial encode/decode */
	int num;
	/*
	* The length is either the output line length (in input bytes) or the
	* shortest input line length that is ok.  Once decoding begins, the
	* length is adjusted up each time a longer line is decoded
	*/
	int length;
	/* data to encode */
	unsigned char enc_data[80];
	/* number read on current line */
	int line_num;
	unsigned int flags;
};


//extern const EVP_PKEY_ASN1_METHOD cmac_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD dh_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD dhx_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[5];
//extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD ecx25519_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD ecx448_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD ed25519_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD ed448_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD sm2_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD poly1305_asn1_meth;
//
//extern const EVP_PKEY_ASN1_METHOD hmac_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[2];
//extern const EVP_PKEY_ASN1_METHOD rsa_pss_asn1_meth;
//extern const EVP_PKEY_ASN1_METHOD siphash_asn1_meth;

/*
* These are used internally in the ASN1_OBJECT to keep track of whether the
* names and data need to be free()ed
*/
# define ASN1_OBJECT_FLAG_DYNAMIC         0x01/* internal use */
# define ASN1_OBJECT_FLAG_CRITICAL        0x02/* critical x509v3 object id */
# define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04/* internal use */
# define ASN1_OBJECT_FLAG_DYNAMIC_DATA    0x08/* internal use */
struct asn1_object_st {
	const char *sn, *ln;
	int nid;
	int length;
	const unsigned char *data;  /* data remains const after init */
	int flags;                  /* Should we free this one */
};

/* ASN1 print context structure */

struct asn1_pctx_st {
	unsigned long flags;
	unsigned long nm_flags;
	unsigned long cert_flags;
	unsigned long oid_flags;
	unsigned long str_flags;
} /* ASN1_PCTX */;











/*
 * Don't free up md_ctx->pctx in EVP_MD_CTX_reset, use the reserved flag
 * values in evp.h
 */
#define EVP_MD_CTX_FLAG_KEEP_PKEY_CTX   0x0400

struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */ ;

#define EVP_PKEY_FLAG_DYNAMIC   1

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVP_PKEY_CTX *ctx);
    int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*cleanup) (EVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVP_PKEY_CTX *ctx);
    int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init) (EVP_PKEY_CTX *ctx);
    int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);
    int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVP_PKEY_CTX *ctx);
    int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
    int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen);
    int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen);
    int (*check) (EVP_PKEY *pkey);
    int (*public_check) (EVP_PKEY *pkey);
    int (*param_check) (EVP_PKEY *pkey);

    int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
} /* EVP_PKEY_METHOD */ ;


extern const EVP_PKEY_METHOD cmac_pkey_meth;
extern const EVP_PKEY_METHOD dh_pkey_meth;
extern const EVP_PKEY_METHOD dhx_pkey_meth;
extern const EVP_PKEY_METHOD dsa_pkey_meth;
extern const EVP_PKEY_METHOD ec_pkey_meth;
extern const EVP_PKEY_METHOD sm2_pkey_meth;
extern const EVP_PKEY_METHOD ecx25519_pkey_meth;
extern const EVP_PKEY_METHOD ecx448_pkey_meth;
extern const EVP_PKEY_METHOD ed25519_pkey_meth;
extern const EVP_PKEY_METHOD ed448_pkey_meth;
extern const EVP_PKEY_METHOD hmac_pkey_meth;
extern const EVP_PKEY_METHOD rsa_pkey_meth;
extern const EVP_PKEY_METHOD rsa_pss_pkey_meth;
extern const EVP_PKEY_METHOD scrypt_pkey_meth;
extern const EVP_PKEY_METHOD tls1_prf_pkey_meth;
extern const EVP_PKEY_METHOD hkdf_pkey_meth;
extern const EVP_PKEY_METHOD poly1305_pkey_meth;
extern const EVP_PKEY_METHOD siphash_pkey_meth;

struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;

struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    //int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    //int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
} /* EVP_CIPHER */ ;

/* Macros to code block cipher wrappers */

/* Wrapper functions for each cipher mode */

#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))

#define BLOCK_CIPHER_ecb_loop() \
        size_t i, bl; \
        bl = EVP_CIPHER_CTX_cipher(ctx)->block_size;    \
        if (inl < bl) return 1;\
        inl -= bl; \
        for (i=0; i <= inl; i+=bl)

#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
static int cname##_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        BLOCK_CIPHER_ecb_loop() \
            cprefix##_ecb_encrypt(in + i, out + i, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_encrypting(ctx)); \
        return 1;\
}

#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
    static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
        }\
        if (inl) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
        }\
        return 1;\
}

#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) \
            {\
            cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
            }\
        if (inl)\
            cprefix##_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
        return 1;\
}

#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)  \
static int cname##_cfb##cbits##_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
    size_t chunk = EVP_MAXCHUNK;\
    if (cbits == 1)  chunk >>= 3;\
    if (inl < chunk) chunk = inl;\
    while (inl && inl >= chunk)\
    {\
        int num = EVP_CIPHER_CTX_num(ctx);\
        cprefix##_cfb##cbits##_encrypt(in, out, (long) \
            ((cbits == 1) \
                && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) \
                ? chunk*8 : chunk), \
            &EVP_C_DATA(kstruct, ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx),\
            &num, EVP_CIPHER_CTX_encrypting(ctx));\
        EVP_CIPHER_CTX_set_num(ctx, num);\
        inl -= chunk;\
        in += chunk;\
        out += chunk;\
        if (inl < chunk) chunk = inl;\
    }\
    return 1;\
}

#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)

#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size, \
                          key_len, iv_len, flags, init_key, cleanup, \
                          set_asn1, get_asn1, ctrl) \
static const EVP_CIPHER cname##_##mode = { \
        nid##_##nmode, block_size, key_len, iv_len, \
        flags | EVP_CIPH_##MODE##_MODE, \
        init_key, \
        cname##_##mode##_cipher, \
        cleanup, \
        sizeof(kstruct), \
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
}; \
const EVP_CIPHER *EVP_##cname##_##mode(void) { return &cname##_##mode; }

#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, \
                             iv_len, flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
                  iv_len, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
                             flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
                  0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_defs(cname, kstruct, \
                          nid, block_size, key_len, iv_len, cbits, flags, \
                          init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl)

/*-
#define BLOCK_CIPHER_defs(cname, kstruct, \
                                nid, block_size, key_len, iv_len, flags,\
                                 init_key, cleanup, set_asn1, get_asn1, ctrl)\
static const EVP_CIPHER cname##_cbc = {\
        nid##_cbc, block_size, key_len, iv_len, \
        flags | EVP_CIPH_CBC_MODE,\
        init_key,\
        cname##_cbc_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_cbc(void) { return &cname##_cbc; }\
static const EVP_CIPHER cname##_cfb = {\
        nid##_cfb64, 1, key_len, iv_len, \
        flags | EVP_CIPH_CFB_MODE,\
        init_key,\
        cname##_cfb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_cfb(void) { return &cname##_cfb; }\
static const EVP_CIPHER cname##_ofb = {\
        nid##_ofb64, 1, key_len, iv_len, \
        flags | EVP_CIPH_OFB_MODE,\
        init_key,\
        cname##_ofb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_ofb(void) { return &cname##_ofb; }\
static const EVP_CIPHER cname##_ecb = {\
        nid##_ecb, block_size, key_len, iv_len, \
        flags | EVP_CIPH_ECB_MODE,\
        init_key,\
        cname##_ecb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_ecb(void) { return &cname##_ecb; }
*/

#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid, \
                               block_size, key_len, iv_len, cbits, \
                               flags, init_key, \
                               cleanup, set_asn1, get_asn1, ctrl) \
        BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len, \
                          cbits, flags, init_key, cleanup, set_asn1, \
                          get_asn1, ctrl)

#define IMPLEMENT_CFBR(cipher,cprefix,kstruct,ksched,keysize,cbits,iv_len,fl) \
        BLOCK_CIPHER_func_cfb(cipher##_##keysize,cprefix,cbits,kstruct,ksched) \
        BLOCK_CIPHER_def_cfb(cipher##_##keysize,kstruct, \
                             NID_##cipher##_##keysize, keysize/8, iv_len, cbits, \
                             (fl)|EVP_CIPH_FLAG_DEFAULT_ASN1, \
                             cipher##_init_key, NULL, NULL, NULL, NULL)


# ifndef OPENSSL_NO_EC

#define X25519_KEYLEN        32
#define X448_KEYLEN          56
#define ED448_KEYLEN         57

#define MAX_KEYLEN  ED448_KEYLEN

typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;

#endif

/*
 * Type needs to be a bit field Sub-type needs to be for variations on the
 * method, as in, can it do arbitrary encryption....
 */
struct evp_pkey_st {
    int type;
    int save_type;
    const EVP_PKEY_ASN1_METHOD *ameth;
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;
    int save_parameters;
} /* EVP_PKEY */ ;


void openssl_add_all_ciphers_int(void);
void openssl_add_all_digests_int(void);
void evp_cleanup_int(void);
void evp_app_cleanup_int(void);

/* Pulling defines out of C source files */

#define EVP_RC4_KEY_SIZE 16
#ifndef TLS1_1_VERSION
# define TLS1_1_VERSION   0x0302
#endif

void evp_encode_ctx_set_flags(EVP_ENCODE_CTX *ctx, unsigned int flags);

/* EVP_ENCODE_CTX flags */
/* Don't generate new lines when encoding */
#define EVP_ENCODE_CTX_NO_NEWLINES          1
/* Use the SRP base64 alphabet instead of the standard one */
#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2
