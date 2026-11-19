#ifndef SM4_ALT_H
#define SM4_ALT_H
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/private_access.h"

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT)

#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16

#define MBEDTLS_SM4_ENCRYPT     1
#define MBEDTLS_SM4_DECRYPT     0

typedef struct mbedtls_sm4_context {
    uint8_t key[SM4_KEY_SIZE];
}mbedtls_sm4_context;

void mbedtls_sm4_init(mbedtls_sm4_context *ctx);

void mbedtls_sm4_free(mbedtls_sm4_context *ctx);

int mbedtls_sm4_setkey_enc(mbedtls_sm4_context *ctx, const unsigned char *key);

int mbedtls_sm4_setkey_dec(mbedtls_sm4_context *ctx, const unsigned char *key);

int mbedtls_sm4_crypt_ecb(mbedtls_sm4_context *ctx, int mode, size_t length,
                          const unsigned char *input, unsigned char *output);

int mbedtls_sm4_crypt_ctr(mbedtls_sm4_context *ctx, size_t length, size_t *nc_off,
                          unsigned char nonce_counter[16], unsigned char stream_block[16],
                          const unsigned char *input, unsigned char *output);

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT */

#endif /* SM4_ALT_H */