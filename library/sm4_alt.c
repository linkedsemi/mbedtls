#include "mbedtls/platform_util.h"
#include <string.h>
#include "mbedtls/sm4_alt.h"

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI)

#include <ls_hal_sm4.h>

#define SM4_IV_SIZE 16

void mbedtls_sm4_init(mbedtls_sm4_context *ctx)
{
    HAL_SM4_Init();
}

void mbedtls_sm4_free(mbedtls_sm4_context *ctx)
{
    HAL_SM4_DeInit();
}

int mbedtls_sm4_setkey(const unsigned char* key)
{
    return HAL_SM4_KeyExpansion(key);
}

int mbedtls_sm4_setiv(mbedtls_sm4_context *ctx, const unsigned char* iv)
{
    memcpy(ctx->iv, iv, SM4_IV_SIZE);
    return 0;
}

int mbedtls_sm4_ecb_encrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    return HAL_SM4_Encrypt(input, output, ilen);
}

int mbedtls_sm4_ecb_decrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    return HAL_SM4_Decrypt(input, output, ilen);
}

int mbedtls_sm4_ctr_crypto(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    HAL_SM4_CTR_Crypt(ctx->iv, input, ilen, output);
    return 0;
}

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI */