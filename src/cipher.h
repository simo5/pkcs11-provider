/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _CIPHER_H
#define _CIPHER_H

#define DISPATCH_CIPHER_FN(alg, name) \
    DECL_DISPATCH_FUNC(cipher, p11prov_##alg, name)

#define DISPATCH_TABLE_CIPHER_FN(cipher, size, mode, mechanism) \
static void *p11prov_##cipher##size##mode##_newctx(void *provctx) \
{ \
    return p11prov_aes_newctx(provctx, size, mechanism); \
} \
static int p11prov_##cipher##size##mode##_get_params(OSSL_PARAM params[]) \
{ \
    return p11prov_aes_get_params(params, size, mechanism); \
} \
static const OSSL_PARAM *p11prov_##cipher##size##mode##_gettable_params(\
    void *provctx) \
{ \
    return p11prov_aes_gettable_params(provctx, size, mechanism); \
} \
const OSSL_DISPATCH ossl_##cipher##size##mode##_functions[] = { \
    { OSSL_FUNC_CIPHER_NEWCTX, \
      (void (*)(void)) p11prov_##cipher##size##mode##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) p11prov_##cipher##_freectx }, \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) p11prov_##cipher##_dupctx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, \
      (void (*)(void))p11prov_##cipher##_encrypt_init }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, \
      (void (*)(void))p11prov_##cipher##_decrypt_init }, \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p11prov_##cipher##_update }, \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p11prov_##cipher##_final }, \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))p11prov_##cipher##_cipher }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS, \
      (void (*)(void)) p11prov_##cipher##size##mode##_get_params }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, \
      (void (*)(void))p11prov_##cipher##_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, \
      (void (*)(void))p11prov_##cipher##_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, \
      (void (*)(void))p11prov_##cipher##size##mode##_gettable_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, \
      (void (*)(void))p11prov_##cipher##_gettable_ctx_params }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, \
     (void (*)(void))p11prov_##cipher##_settable_ctx_params }, \
    OSSL_DISPATCH_END \
};

extern const OSSL_DISPATCH p11prov_aes128ecb_functions[];
extern const OSSL_DISPATCH p11prov_aes192ecb_functions[];
extern const OSSL_DISPATCH p11prov_aes256ecb_functions[];
extern const OSSL_DISPATCH p11prov_aes128cbc_functions[];
extern const OSSL_DISPATCH p11prov_aes192cbc_functions[];
extern const OSSL_DISPATCH p11prov_aes256cbc_functions[];
extern const OSSL_DISPATCH p11prov_aes128ofb_functions[];
extern const OSSL_DISPATCH p11prov_aes192ofb_functions[];
extern const OSSL_DISPATCH p11prov_aes256ofb_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb1_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb1_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb1_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb8_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb8_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb8_functions[];
extern const OSSL_DISPATCH p11prov_aes128ctr_functions[];
extern const OSSL_DISPATCH p11prov_aes192ctr_functions[];
extern const OSSL_DISPATCH p11prov_aes256ctr_functions[];

#endif /* _CIPHER_H */
