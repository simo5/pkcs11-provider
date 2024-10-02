/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "cipher.h"
#include <string.h>
#include "openssl/prov_ssl.h"

DISPATCH_CIPHER_FN(aes, freectx);
DISPATCH_CIPHER_FN(aes, dupctx);
DISPATCH_CIPHER_FN(aes, encrypt_init);
DISPATCH_CIPHER_FN(aes, decrypt_init);
DISPATCH_CIPHER_FN(aes, update);
DISPATCH_CIPHER_FN(aes, final);
DISPATCH_CIPHER_FN(aes, update);
DISPATCH_CIPHER_FN(aes, final);
DISPATCH_CIPHER_FN(aes, cipher);
DISPATCH_CIPHER_FN(aes, get_ctx_params);
DISPATCH_CIPHER_FN(aes, set_ctx_params);
DISPATCH_CIPHER_FN(aes, gettable_ctx_params);
DISPATCH_CIPHER_FN(aes, settable_ctx_params);

struct p11prov_aes_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *key;
    CK_MECHANISM mech;
    int keysize;
};

static void *p11prov_aes_newctx(void *provctx, int size, CK_ULONG mechanism)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    struct p11prov_aes_ctx *aesctx;

    P11PROV_debug("AES(%d) new context for mechanism %ld", size, mechanism);

    aesctx = OPENSSL_zalloc(sizeof(struct p11prov_aes_ctx));
    if (aesctx == NULL) {
        return NULL;
    }

    aesctx->provctx = ctx;
    aesctx->mech.mechanism = mechanism;
    aesctx->keysize = size;

    return aesctx;
}

static int p11prov_aes_get_params(OSSL_PARAM params[], int size,
                                  CK_ULONG mechanism)
{
    return RET_OSSL_ERR;
}

static const OSSL_PARAM *p11prov_aes_gettable_params(void *provctx, int size,
                                                     CK_ULONG mechanism)
{
    return NULL;
}


static void p11prov_aes_freectx(void *ctx)
{
    struct p11prov_aes_ctx *aesctx = (struct p11prov_aes_ctx *)ctx;

    if (aesctx == NULL) {
        return;
    }

    p11prov_obj_free(aesctx->key);
    OPENSSL_clear_free(aesctx->mech.pParameter, aesctx->mech.ulParameterLen);
    OPENSSL_clear_free(aesctx, sizeof(struct p11prov_aes_ctx));
}

static void *p11prov_aes_dupctx(void *ctx)
{
    return NULL;
}

static int p11prov_aes_encrypt_init(void *ctx,
                                    const unsigned char *key,
                                    size_t keylen,
                                    const unsigned char *iv,
                                    size_t ivlen,
                                    const OSSL_PARAM params[])
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_decrypt_init(void *ctx,
                                    const unsigned char *key,
                                    size_t keylen,
                                    const unsigned char *iv,
                                    size_t ivlen,
                                    const OSSL_PARAM params[])
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_update(void *ctx,
                              unsigned char *out, size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    /* TODO: if block else stream */
    return RET_OSSL_ERR;
}

static int p11prov_aes_final(void *ctx,
                             unsigned char *out, size_t *outl, size_t outsize)
{
    /* TODO: if block else stream */
    return RET_OSSL_ERR;
}

static int p11prov_aes_cipher(void *ctx,
                              unsigned char *out, size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return RET_OSSL_ERR;
}

static const OSSL_PARAM *p11prov_aes_gettable_ctx_params(void *ctx,
                                                         void *provctx)
{
    return NULL;
}

static const OSSL_PARAM *p11prov_aes_settable_ctx_params(void *ctx,
                                                         void *provctx)
{
    return NULL;
}

DISPATCH_TABLE_CIPHER_FN(aes, 128, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cbc, CKM_AES_CBC);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cbc, CKM_AES_CBC);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cbc, CKM_AES_CBC);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cts, CKM_AES_CTS);
