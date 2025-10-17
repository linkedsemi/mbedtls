#include <stdint.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/aes.h"
#include <string.h>
#include <ls_hal_crypt.h>
#include "mbedtls/error.h"
#include "common.h"
#if CONFIG_SOC_LSQSH
    #if CONFIG_AES_CLOCK_RESET
        #include "reg_sysc_sec_cpu.h"
    #endif
#endif

#if defined(CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI)
#define AES_BLOCK_SIZE 16

void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_aes_context));
#if CONFIG_SOC_LS1010
    HAL_LSCRYPT_Init();
#elif CONFIG_SOC_LSQSH
    #if CONFIG_AES_CLOCK_RESET
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CRYPT_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_CRYPT_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_CRYPT_MASK;
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_CRYPT_MASK;
    #endif
#endif
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
    if (keybits == 128)
        keysize = AES_KEY_128;
    else if (keybits == 192)
        keysize = AES_KEY_192;
    else if (keybits == 256)
        keysize = AES_KEY_256;
    else
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    return HAL_LSCRYPT_AES_Key_Config((uint32_t *)key, keysize);
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    return mbedtls_aes_setkey_enc(ctx, key, keybits);
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

int mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx,
                             int mode,
                             size_t length,
                             size_t *iv_off,
                             unsigned char iv[16],
                             const unsigned char *input,
                             unsigned char *output)
{
    int c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    n = *iv_off;

    if (n > 15) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    if (mode == MBEDTLS_AES_DECRYPT) {
        while (length--) {
            if (n == 0) {
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
                if (ret != 0) {
                    goto exit;
                }
            }

            c = *input++;
            *output++ = (unsigned char) (c ^ iv[n]);
            iv[n] = (unsigned char) c;

            n = (n + 1) & 0x0F;
        }
    } else {
        while (length--) {
            if (n == 0) {
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
                if (ret != 0) {
                    goto exit;
                }
            }

            iv[n] = *output++ = (unsigned char) (iv[n] ^ *input++);

            n = (n + 1) & 0x0F;
        }
    }

    *iv_off = n;
    ret = 0;

exit:
    return ret;
}

int mbedtls_aes_crypt_cfb8(mbedtls_aes_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char c;
    unsigned char ov[17];

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
    while (length--) {
        memcpy(ov, iv, 16);
        ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
        if (ret != 0) {
            goto exit;
        }

        if (mode == MBEDTLS_AES_DECRYPT) {
            ov[16] = *input;
        }

        c = *output++ = (unsigned char) (iv[0] ^ *input++);

        if (mode == MBEDTLS_AES_ENCRYPT) {
            ov[16] = c;
        }

        memcpy(iv, ov + 1, 16);
    }
    ret = 0;

exit:
    return ret;
}

int mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *iv_off,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    int ret = 0;
    size_t n;

    n = *iv_off;

    if (n > 15) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    while (length--) {
        if (n == 0) {
            ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            if (ret != 0) {
                goto exit;
            }
        }
        *output++ =  *input++ ^ iv[n];

        n = (n + 1) & 0x0F;
    }

    *iv_off = n;

exit:
    return ret;
}

int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    return HAL_LSCRYPT_AES_CTR_Crypt(nonce_counter, (uint8_t*)input, length, (uint8_t*)output);
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
const unsigned char *aes_xts_key1;
unsigned int aes_xts_key1bits;
static inline void mbedtls_gf128mul_x_ble(unsigned char r[16],
                                          const unsigned char x[16])
{
    uint64_t a, b, ra, rb;

    a = MBEDTLS_GET_UINT64_LE(x, 0);
    b = MBEDTLS_GET_UINT64_LE(x, 8);

    ra = (a << 1)  ^ 0x0087 >> (8 - ((b >> 63) << 3));
    rb = (a >> 63) | (b << 1);

    MBEDTLS_PUT_UINT64_LE(ra, r, 0);
    MBEDTLS_PUT_UINT64_LE(rb, r, 8);
}

static int mbedtls_aes_xts_decode_keys(const unsigned char *key,
                                       unsigned int keybits,
                                       const unsigned char **key1,
                                       unsigned int *key1bits,
                                       const unsigned char **key2,
                                       unsigned int *key2bits)
{
    const unsigned int half_keybits = keybits / 2;
    const unsigned int half_keybytes = half_keybits / 8;

    switch (keybits) {
        case 256: break;
        case 512: break;
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    *key1bits = half_keybits;
    *key2bits = half_keybits;
    *key1 = &key[0];
    *key2 = &key[half_keybytes];

    return 0;
}

void mbedtls_aes_xts_init(mbedtls_aes_xts_context *ctx)
{
    mbedtls_aes_init(&ctx->crypt);
    mbedtls_aes_init(&ctx->tweak);
}

int mbedtls_aes_xts_setkey_enc(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    ret = mbedtls_aes_xts_decode_keys(key, keybits, &key1, &key1bits,
                                      &key2, &key2bits);
    if (ret != 0) {
        return ret;
    }

    aes_xts_key1 = key1;
    aes_xts_key1bits = key1bits;

    /* Set the tweak key. Always set tweak key for the encryption mode. */
    return mbedtls_aes_setkey_enc(&ctx->tweak, key2, key2bits);
}

int mbedtls_aes_xts_setkey_dec(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits)
{
    return mbedtls_aes_xts_setkey_enc(ctx, key, keybits);
}

int mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx,
                          int mode,
                          size_t length,
                          const unsigned char data_unit[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t blocks = length / 16;
    size_t leftover = length % 16;
    unsigned char tweak[16] = {0};
    unsigned char prev_tweak[16];
    unsigned char tmp[16];

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    /* Data units must be at least 16 bytes long. */
    if (length < 16) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
    if (length > (1 << 20) * 16) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* Compute the tweak. */
    ret = mbedtls_aes_crypt_ecb(&ctx->tweak, MBEDTLS_AES_ENCRYPT,
                                data_unit, tweak);
    if (ret != 0) {
        return ret;
    }

    while (blocks--) {
        if (MBEDTLS_UNLIKELY(leftover && (mode == MBEDTLS_AES_DECRYPT) && blocks == 0)) {
            /* We are on the last block in a decrypt operation that has
             * leftover bytes, so we need to use the next tweak for this block,
             * and this tweak for the leftover bytes. Save the current tweak for
             * the leftovers and then update the current tweak for use on this,
             * the last full block. */
            memcpy(prev_tweak, tweak, sizeof(tweak));
            mbedtls_gf128mul_x_ble(tweak, tweak);
        }

        mbedtls_xor(tmp, input, tweak, 16);

        /* This is different from the software configuration of mbedtls */
        ret = mbedtls_aes_setkey_enc(&ctx->crypt, aes_xts_key1, aes_xts_key1bits);
        if (ret != 0) {
            return ret;
        }

        ret = mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
        if (ret != 0) {
            return ret;
        }

        mbedtls_xor(output, tmp, tweak, 16);

        /* Update the tweak for the next block. */
        mbedtls_gf128mul_x_ble(tweak, tweak);

        output += 16;
        input += 16;
    }

    if (leftover) {
        /* If we are on the leftover bytes in a decrypt operation, we need to
         * use the previous tweak for these bytes (as saved in prev_tweak). */
        unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;

        /* We are now on the final part of the data unit, which doesn't divide
         * evenly by 16. It's time for ciphertext stealing. */
        size_t i;
        unsigned char *prev_output = output - 16;

        /* Copy ciphertext bytes from the previous block to our output for each
         * byte of ciphertext we won't steal. */
        for (i = 0; i < leftover; i++) {
            output[i] = prev_output[i];
        }

        /* Copy the remainder of the input for this final round. */
        mbedtls_xor(tmp, input, t, leftover);

        /* Copy ciphertext bytes from the previous block for input in this
         * round. */
        mbedtls_xor(tmp + i, prev_output + i, t + i, 16 - i);

        ret = mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
        if (ret != 0) {
            return ret;
        }

        /* Write the result back to the previous block, overriding the previous
         * output we copied. */
        mbedtls_xor(prev_output, tmp, t, 16);
    }

    return 0;
}

void mbedtls_aes_xts_free(mbedtls_aes_xts_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_aes_free(&ctx->crypt);
    mbedtls_aes_free(&ctx->tweak);
}
#endif /*MBEDTLS_CIPHER_MODE_XTS*/
#endif /* CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI */