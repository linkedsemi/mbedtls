#ifndef SM4_ALT_H
#define SM4_ALT_H
#include <stdint.h>
#include "mbedtls/private_access.h"

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI)

#define SM4_IV_SIZE 16

typedef struct mbedtls_sm4_context {
    uint8_t iv[SM4_IV_SIZE];
}mbedtls_sm4_context;

void mbedtls_sm4_init(mbedtls_sm4_context *ctx);

void mbedtls_sm4_free(mbedtls_sm4_context *ctx);

int mbedtls_sm4_setkey(const unsigned char* key);

int mbedtls_sm4_setiv(mbedtls_sm4_context *ctx, const unsigned char* iv);

int mbedtls_sm4_ecb_encrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen);

int mbedtls_sm4_ecb_decrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen);

int mbedtls_sm4_ctr_crypto(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen);

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI */

#endif /* SM4_ALT_H */