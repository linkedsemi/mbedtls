#include <stdint.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/aes.h"
#include <string.h>
#include <ls_hal_crypt.h>
#include "mbedtls/error.h"
#include "common.h"
#include "ctr.h"
#if CONFIG_SOC_LSQSH
    #include "field_manipulate.h"
    #include "reg_crypt_type.h"
    #include "reg_sysc_sec_cpu.h"
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
#if CONFIG_SOC_LS1010
        HAL_LSCRYPT_DeInit();
#elif CONFIG_SOC_LSQSH
    #if CONFIG_SHA256_CLOCK_RESET
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CRYPT_MASK;
    #endif
#endif
}

static void aes_config(bool iv_en, bool enc, bool ie, bool dmaen, bool fifoen, uint8_t type, uint8_t mode)
{
    MODIFY_REG(LSCRYPT->CR,CRYPT_CRYSEL_MASK|CRYPT_DMAEN_MASK|CRYPT_FIFOODR_MASK|CRYPT_FIFOEN_MASK|CRYPT_TYPE_MASK|CRYPT_IE_MASK|CRYPT_IVREN_MASK|CRYPT_MODE_MASK|CRYPT_ENCS_MASK,
        0<<CRYPT_CRYSEL_POS|(dmaen?1:0)<<CRYPT_DMAEN_POS|(fifoen?1:0)<<CRYPT_FIFOODR_POS|(fifoen?1:0)<<CRYPT_FIFOEN_POS|type<<CRYPT_TYPE_POS|(ie?1:0)<<CRYPT_IE_POS|(iv_en?1:0)<<CRYPT_IVREN_POS|mode<<CRYPT_MODE_POS|(enc?1:0)<<CRYPT_ENCS_POS);
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    uint8_t keysize = 0;
    uint32_t *u32_key = (uint32_t *)key;

    do{
        if(keybits == 128)
        {
            keysize = AES_KEY_128;
            LSCRYPT->KEY3 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY2 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY1 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY0 = __builtin_bswap32(*u32_key++);
            break;
        }
        if(keybits == 192)
        {
            keysize = AES_KEY_192;
            LSCRYPT->KEY5 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY4 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY3 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY2 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY1 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY0 = __builtin_bswap32(*u32_key++);
            break;
        }
        if(keybits == 256)
        {
            keysize = AES_KEY_256;
            LSCRYPT->KEY7 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY6 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY5 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY4 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY3 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY2 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY1 = __builtin_bswap32(*u32_key++);
            LSCRYPT->KEY0 = __builtin_bswap32(*u32_key++);
            break;
        }
    }while(0);
    REG_FIELD_WR(LSCRYPT->CR,CRYPT_AESKS,keysize);
    return 0;
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

    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    if(mode == MBEDTLS_AES_ENCRYPT)
    {
        aes_config(false, true, false, false, false, 0x2, 0x0);
    }else{
        aes_config(false, false, false, false, false, 0x2, 0x0);
    }

    LSCRYPT->DATA3 = *in++;
    LSCRYPT->DATA2 = *in++;
    LSCRYPT->DATA1 = *in++;
    LSCRYPT->DATA0 = *in++;
    REG_FIELD_WR(LSCRYPT->CR,CRYPT_GO,1);
    while (REG_FIELD_RD(LSCRYPT->SR, CRYPT_AESRIF) == 0);
    LSCRYPT->ICFR = CRYPT_AESIF_MASK;
    *out++ = LSCRYPT->RES3;
    *out++ = LSCRYPT->RES2;
    *out++ = LSCRYPT->RES1;
    *out++ = LSCRYPT->RES0;
    return 0;
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

    __ASSERT_NO_MSG(length % 16 == 0);

    const unsigned char * end_addr = input + length;
    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;
    uint32_t *u32_iv = (uint32_t *)iv;

    LSCRYPT->IVR3 = __builtin_bswap32(*u32_iv++);
    LSCRYPT->IVR2 = __builtin_bswap32(*u32_iv++);
    LSCRYPT->IVR1 = __builtin_bswap32(*u32_iv++);
    LSCRYPT->IVR0 = __builtin_bswap32(*u32_iv++);

    if(mode == MBEDTLS_AES_ENCRYPT)
    {
        aes_config(true, true, false, false, false, 0x0, 0x1);
    }else{
        aes_config(true, false, false, false, false, 0x0, 0x1);
    }

    while(in < (uint32_t*)end_addr)
    {
        LSCRYPT->DATA3 = __builtin_bswap32(*in++);
        LSCRYPT->DATA2 = __builtin_bswap32(*in++);
        LSCRYPT->DATA1 = __builtin_bswap32(*in++);
        LSCRYPT->DATA0 = __builtin_bswap32(*in++);
        REG_FIELD_WR(LSCRYPT->CR, CRYPT_GO, 1);
        while (REG_FIELD_RD(LSCRYPT->SR, CRYPT_AESRIF) == 0);
        LSCRYPT->CR &= ~CRYPT_IVREN_MASK;
        LSCRYPT->ICFR = CRYPT_AESIF_MASK;
        *out++ = __builtin_bswap32(LSCRYPT->RES3);
        *out++ = __builtin_bswap32(LSCRYPT->RES2);
        *out++ = __builtin_bswap32(LSCRYPT->RES1);
        *out++ = __builtin_bswap32(LSCRYPT->RES0);
    }
    return 0;
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
    const unsigned char * end_addr = input + length;
    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    uint32_t *u32_counter = (uint32_t *)nonce_counter;

    aes_config(false, true, false, false, false, 0x0, 0x2);

    LSCRYPT->IVR3 = __builtin_bswap32(*u32_counter++);
    LSCRYPT->IVR2 = __builtin_bswap32(*u32_counter++);
    LSCRYPT->IVR1 = __builtin_bswap32(*u32_counter++);
    LSCRYPT->IVR0 = __builtin_bswap32(*u32_counter++);

    while (in < (uint32_t*)end_addr)
    {
        LSCRYPT->DATA3 = __builtin_bswap32(*in++);
        LSCRYPT->DATA2 = __builtin_bswap32(*in++);
        LSCRYPT->DATA1 = __builtin_bswap32(*in++);
        LSCRYPT->DATA0 = __builtin_bswap32(*in++);
        REG_FIELD_WR(LSCRYPT->CR,CRYPT_GO,1);
        while (REG_FIELD_RD(LSCRYPT->SR, CRYPT_AESRIF) == 0);
        LSCRYPT->ICFR = CRYPT_AESIF_MASK;
        *out++ = __builtin_bswap32(LSCRYPT->RES3);
        *out++ = __builtin_bswap32(LSCRYPT->RES2);
        *out++ = __builtin_bswap32(LSCRYPT->RES1);
        *out++ = __builtin_bswap32(LSCRYPT->RES0);
    }
    return 0;
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