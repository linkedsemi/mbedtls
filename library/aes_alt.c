#include <stdint.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/aes.h"
#include <string.h>
#include <ls_hal_crypt.h>

#if defined(CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI)
#define AES_BLOCK_SIZE 16

void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_aes_context));
    HAL_LSCRYPT_Init();
}

void mbedtls_aes_free(mbedtls_aes_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_aes_context));
    HAL_LSCRYPT_DeInit();
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    uint8_t keysize = 0;
    if (keybits == 16)
        keysize = AES_KEY_128;
    else if (keybits == 24)
        keysize = AES_KEY_192;
    else if (keybits == 32)
        keysize = AES_KEY_256;
    else
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    return HAL_LSCRYPT_AES_Key_Config((uint32_t *)key, keysize);
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16])
{
    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    uint32_t length = AES_BLOCK_SIZE;

    if(mode == MBEDTLS_AES_ENCRYPT)
    {
        return HAL_LSCRYPT_AES_ECB_Encrypt(input, length, output, &length);
    }else{
        return HAL_LSCRYPT_AES_ECB_Decrypt(input, length, output, &length);
    }

}

int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    HAL_LSCRYPT_SET_IV((uint32_t *)iv);

    if(mode == MBEDTLS_AES_ENCRYPT)
    {
        return HAL_LSCRYPT_AES_CBC_Encrypt(input, length, output, &length);
    }else{
        return HAL_LSCRYPT_AES_CBC_Decrypt(input, length, output, &length);
    }

}
#endif /* CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI */