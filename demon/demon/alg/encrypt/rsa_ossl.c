/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//
#include "bn.h"
#include "rsa_local.h"
#include "constant_time.h"

static int rsa_ossl_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
static int rsa_ossl_private_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int rsa_ossl_public_decrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
static int rsa_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int rsa_ossl_mod_exp(BIGNUM *r0, const BIGNUM *i, RSA *rsa,  BN_CTX *ctx);
static int rsa_ossl_init(RSA *rsa);
static int rsa_ossl_finish(RSA *rsa);
 static RSA_METHOD rsa_pkcs1_ossl_meth = {
     "OpenSSL PKCS#1 RSA",
     rsa_ossl_public_encrypt,
     rsa_ossl_public_decrypt,     /* signature verification */
     rsa_ossl_private_encrypt,    /* signing */
     rsa_ossl_private_decrypt,
     rsa_ossl_mod_exp,
     BN_mod_exp_mont,            /* XXX probably we should not use Montgomery
                                  * if e == 3 */
     rsa_ossl_init,
     rsa_ossl_finish,
     RSA_FLAG_FIPS_METHOD,       /* flags */
     NULL,
     0,                          /* rsa_sign */
     0,                          /* rsa_verify */
     NULL,                       /* rsa_keygen */
     NULL                        /* rsa_multi_prime_keygen */
 };



 void RSA_free(RSA *r)
 {
	 if (r == NULL)
		 return;

	 if (r->meth != NULL && r->meth->finish != NULL)
		 r->meth->finish(r);

	 BN_free(r->n);
	 BN_free(r->e);
	 BN_clear_free(r->d);
 }

 RSA *RSA_new_method()
 {
	 RSA *ret = _zalloc(sizeof(*ret));

	 if (ret == NULL) {
		 return NULL;
	 }
	 ret->d = NULL;
	 ret->e = NULL;
	 ret->n = NULL;

	 ret->meth = &rsa_pkcs1_ossl_meth;

	 if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
		 goto err;
	 }

	 return ret;

 err:
	 RSA_free(ret);
	 return NULL;
 }

static int rsa_ossl_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        return -1;
    }

    if (BN_ucmp(rsa->n, rsa->e) <= 0) {
        return -1;
    }

    /* for large moduli, enforce exponent limit */
    if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
        if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
            return -1;
        }
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char *)_malloc(num);
    if (ret == NULL || buf == NULL) {
        goto err;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
        break;
    case RSA_SSLV23_PADDING:
        i = RSA_padding_add_SSLv23(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    default:
        goto err;
    }
    if (i <= 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        /* usually the padding functions would catch this */
        goto err;
    }

// 	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
// 		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, rsa->lock,
// 			rsa->n, ctx))
//             goto err;

    if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
                               rsa->_method_mod_n))
        goto err;

    /*
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     */
    r = BN_bn2binpad(ret, to, num);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	_clear_free(buf, num);
    return r;
}

static BN_BLINDING *rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
	return NULL;
 //   BN_BLINDING *ret;

 //   CRYPTO_THREAD_write_lock(rsa->lock);

 //   if (rsa->blinding == NULL) {
 //       rsa->blinding = RSA_setup_blinding(rsa, ctx);
 //   }

 //   ret = rsa->blinding;
 //   if (ret == NULL)
 //       goto err;

 //   if (BN_BLINDING_is_current_thread(ret)) {
 //       /* rsa->blinding is ours! */

 //       *local = 1;
 //   } else {
 //       /* resort to rsa->mt_blinding instead */

 //       /*
 //        * instructs rsa_blinding_convert(), rsa_blinding_invert() that the
 //        * BN_BLINDING is shared, meaning that accesses require locks, and
 //        * that the blinding factor must be stored outside the BN_BLINDING
 //        */
 //       *local = 0;

 //       if (rsa->mt_blinding == NULL) {
 //           rsa->mt_blinding = RSA_setup_blinding(rsa, ctx);
 //       }
 //       ret = rsa->mt_blinding;
 //   }

 //err:
 //   CRYPTO_THREAD_unlock(rsa->lock);
 //   return ret;
}

// static int rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,
//                                 BN_CTX *ctx)
// {
//     if (unblind == NULL) {
//         /*
//          * Local blinding: store the unblinding factor in BN_BLINDING.
//          */
//         return BN_BLINDING_convert_ex(f, NULL, b, ctx);
//     } else {
//         /*
//          * Shared blinding: store the unblinding factor outside BN_BLINDING.
//          */
//         int ret;
// 
//         BN_BLINDING_lock(b);
//         ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
//         BN_BLINDING_unlock(b);
// 
//         return ret;
//     }
// }

// static int rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,
//                                BN_CTX *ctx)
// {
//     /*
//      * For local blinding, unblind is set to NULL, and BN_BLINDING_invert_ex
//      * will use the unblinding factor stored in BN_BLINDING. If BN_BLINDING
//      * is shared between threads, unblind must be non-null:
//      * BN_BLINDING_invert_ex will then use the local unblinding factor, and
//      * will only read the modulus from BN_BLINDING. In both cases it's safe
//      * to access the blinding without a lock.
//      */
//     return BN_BLINDING_invert_ex(f, unblind, b, ctx);
// }

/* signing */
static int rsa_ossl_private_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret, *res;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    /*
     * Used only if the blinding structure is shared. A non-NULL unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     */
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char *)_malloc(num);
    if (ret == NULL || buf == NULL) {
        goto err;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
        break;
    case RSA_X931_PADDING:
        i = RSA_padding_add_X931(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    case RSA_SSLV23_PADDING:
    default:
        goto err;
    }
    if (i <= 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        /* usually the padding functions would catch this */
        goto err;
    }

    //if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
    //    if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, rsa->lock,
    //                                rsa->n, ctx))
    //        goto err;

    //if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
    //    blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
    //    if (blinding == NULL) {
    //        goto err;
    //    }
    //}

//     if (blinding != NULL) {
//         if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
//             goto err;
//         }
//         if (!rsa_blinding_convert(blinding, f, unblind, ctx))
//             goto err;
//     }

	/*    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
			(rsa->version == RSA_ASN1_VERSION_MULTI) ||
			((rsa->p != NULL) &&
			 (rsa->q != NULL) &&
			 (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
			if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
				goto err;
		} else */ {
        BIGNUM *d = BN_new();
        if (d == NULL) {
            goto err;
        }
        if (rsa->d == NULL) {
            BN_free(d);
            goto err;
        }
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);

        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n)) {
            BN_free(d);
            goto err;
        }
        /* We MUST free d before any further use of rsa->d */
        BN_free(d);
    }

//     if (blinding)
//         if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
//             goto err;

    if (padding == RSA_X931_PADDING) {
        if (!BN_sub(f, rsa->n, ret))
            goto err;
        if (BN_cmp(ret, f) > 0)
            res = f;
        else
            res = ret;
    } else {
        res = ret;
    }

    /*
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     */
    r = BN_bn2binpad(res, to, num);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	_clear_free(buf, num);
    return r;
}

static int rsa_ossl_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int j, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    /*
     * Used only if the blinding structure is shared. A non-NULL unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     */
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char *)_malloc(num);
    if (ret == NULL || buf == NULL) {
        goto err;
    }

    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        goto err;
    }

    /* make data into a big number */
    if (BN_bin2bn(from, (int)flen, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        goto err;
    }

    //if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
    //    blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
    //    if (blinding == NULL) {
    //        goto err;
    //    }
    //}

    //if (blinding != NULL) {
    //    if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
    //        goto err;
    //    }
    //    if (!rsa_blinding_convert(blinding, f, unblind, ctx))
    //        goto err;
    //}

    ///* do the decrypt */
    //if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
    //    (rsa->version == RSA_ASN1_VERSION_MULTI) ||
    //    ((rsa->p != NULL) &&
    //     (rsa->q != NULL) &&
    //     (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
    //    if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
    //        goto err;
    //} else 
	{
        BIGNUM *d = BN_new();
        if (d == NULL) {
            goto err;
        }
        if (rsa->d == NULL) {
            BN_free(d);
            goto err;
        }
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);

        //if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
        //    if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, rsa->lock,
        //                                rsa->n, ctx)) {
        //        BN_free(d);
        //        goto err;
        //    }
        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n)) {
            BN_free(d);
            goto err;
        }
        /* We MUST free d before any further use of rsa->d */
        BN_free(d);
    }

    //if (blinding)
    //    if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
    //        goto err;

    j = BN_bn2binpad(ret, buf, num);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
        break;
    case RSA_PKCS1_OAEP_PADDING:
        r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
        break;
    case RSA_SSLV23_PADDING:
        r = RSA_padding_check_SSLv23(to, num, buf, j, num);
        break;
    case RSA_NO_PADDING:
        memcpy(to, buf, (r = j));
        break;
    default:
        goto err;
    }
    //err_clear_last_constant_time(1 & ~constant_time_msb(r));

err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	_clear_free(buf, num);
    return r;
}

/* signature verification */
static int rsa_ossl_public_decrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        return -1;
    }

    if (BN_ucmp(rsa->n, rsa->e) <= 0) {
        return -1;
    }

    /* for large moduli, enforce exponent limit */
    if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
        if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
            return -1;
        }
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char *)_malloc(num);
    if (ret == NULL || buf == NULL) {
        goto err;
    }

    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        goto err;
    }

    if (BN_bin2bn(from, flen, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        goto err;
    }

    //if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
    //    if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, rsa->lock,
    //                                rsa->n, ctx))
    //        goto err;

    if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
                               rsa->_method_mod_n))
        goto err;

    if ((padding == RSA_X931_PADDING) && ((bn_get_words(ret)[0] & 0xf) != 12))
        if (!BN_sub(ret, rsa->n, ret))
            goto err;

    i = BN_bn2binpad(ret, buf, num);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_1(to, num, buf, i, num);
        break;
    case RSA_X931_PADDING:
        r = RSA_padding_check_X931(to, num, buf, i, num);
        break;
    case RSA_NO_PADDING:
        memcpy(to, buf, (r = i));
        break;
    default:
        goto err;
    }

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	_clear_free(buf, num);
    return r;
}

static int rsa_ossl_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	return 1;
}

static int rsa_ossl_init(RSA *rsa)
{
	return 1;
}

static int rsa_ossl_finish(RSA *rsa)
{
    return 1;
}
