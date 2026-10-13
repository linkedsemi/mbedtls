#include <stdint.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/aes.h"
#include <string.h>
#include <ls_hal_crypt.h>
#include "mbedtls/error.h"
#include "common.h"
#include "ctr.h"
#include <zephyr/kernel.h>
#if CONFIG_SOC_LSQSH
    #include "field_manipulate.h"
    #include "reg_crypt_type.h"
    #include "reg_sysc_sec_cpu.h"
#endif

#if defined(CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI)
#define AES_BLOCK_SIZE 16
#define AES_HW_WAIT_TIMEOUT_MS 100

/* Serialize access to the shared LSCRYPT register bank. CBC/CTR chain blocks
 * inside the hardware, so the lock must span a whole buffer, not one block. */
static K_MUTEX_DEFINE(aes_hw_mutex);

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

    /* Zero the shared hardware KEY registers so key material does not linger
     * until the next operation overwrites it. Every crypt entry reloads its
     * own key (aes_hw_setkey) before use, so this does not disturb other live
     * contexts. */
    k_mutex_lock(&aes_hw_mutex, K_FOREVER);
    LSCRYPT->KEY0 = 0;
    LSCRYPT->KEY1 = 0;
    LSCRYPT->KEY2 = 0;
    LSCRYPT->KEY3 = 0;
    LSCRYPT->KEY4 = 0;
    LSCRYPT->KEY5 = 0;
    LSCRYPT->KEY6 = 0;
    LSCRYPT->KEY7 = 0;
#if CONFIG_SOC_LS1010
        HAL_LSCRYPT_DeInit();
#elif CONFIG_SOC_LSQSH
    /* 不能关时钟：所有 AES context 共享同一套硬件 KEY 寄存器，
     * 关掉会导致其他 context 无法访问硬件。 */
#endif
    k_mutex_unlock(&aes_hw_mutex);
}

static void aes_config(bool iv_en, bool enc, bool ie, bool dmaen, bool fifoen, uint8_t type, uint8_t mode)
{
    MODIFY_REG(LSCRYPT->CR,CRYPT_CRYSEL_MASK|CRYPT_DMAEN_MASK|CRYPT_FIFOODR_MASK|CRYPT_FIFOEN_MASK|CRYPT_TYPE_MASK|CRYPT_IE_MASK|CRYPT_IVREN_MASK|CRYPT_MODE_MASK|CRYPT_ENCS_MASK,
        0<<CRYPT_CRYSEL_POS|(dmaen?1:0)<<CRYPT_DMAEN_POS|(fifoen?1:0)<<CRYPT_FIFOODR_POS|(fifoen?1:0)<<CRYPT_FIFOEN_POS|type<<CRYPT_TYPE_POS|(ie?1:0)<<CRYPT_IE_POS|(iv_en?1:0)<<CRYPT_IVREN_POS|mode<<CRYPT_MODE_POS|(enc?1:0)<<CRYPT_ENCS_POS);
}

/* Write key to hardware KEY registers. Shared by setkey and crypt functions
 * to ensure each context's own key is loaded before every hardware operation. */
static int aes_hw_setkey(const unsigned char *key, unsigned int keybits)
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
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }while(0);
    REG_FIELD_WR(LSCRYPT->CR,CRYPT_AESKS,keysize);
    return 0;
}

/* Poll the engine with a deadline: if AESRIF is never set (clock gated, reset
 * not released, or hardware fault) the caller must not spin forever. */
static int aes_hw_wait_done(void)
{
    int64_t start = k_uptime_get();

    while (REG_FIELD_RD(LSCRYPT->SR, CRYPT_AESRIF) == 0) {
        if ((k_uptime_get() - start) > AES_HW_WAIT_TIMEOUT_MS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }
    return 0;
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    int ret;

    if (ctx == NULL || key == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);
    ret = aes_hw_setkey(key, keybits);
    k_mutex_unlock(&aes_hw_mutex);
    if (ret != 0) {
        return ret;
    }

    /* Save key in context so crypt_ecb/crypt_cbc/crypt_ctr can restore it
     * when another context has overwritten the hardware KEY registers. */
    memcpy(ctx->key, key, keybits / 8);
    ctx->keybits = keybits;

    return 0;
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    return mbedtls_aes_setkey_enc(ctx, key, keybits);
}

/* Hardware ECB on a single block. The caller must hold aes_hw_mutex. */
static int aes_crypt_ecb_raw(mbedtls_aes_context *ctx,
                             int mode,
                             const unsigned char input[16],
                             unsigned char output[16])
{
    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    /* Restore this context's key — a different context may have overwritten
     * the shared hardware KEY registers since the last setkey call. Failing
     * here means the context was never keyed; do not run with a stale key. */
    if (aes_hw_setkey(ctx->key, ctx->keybits) != 0) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

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
    if (aes_hw_wait_done() != 0) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    LSCRYPT->ICFR = CRYPT_AESIF_MASK;
    *out++ = LSCRYPT->RES3;
    *out++ = LSCRYPT->RES2;
    *out++ = LSCRYPT->RES1;
    *out++ = LSCRYPT->RES0;
    return 0;
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16])
{
    int ret;

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    if (ctx == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);
    ret = aes_crypt_ecb_raw(ctx, mode, input, output);
    k_mutex_unlock(&aes_hw_mutex);

    return ret;
}

int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    int ret = 0;

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    if (ctx == NULL || iv == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    /* Nothing to do if length is zero. */
    if (length == 0) {
        return 0;
    }

    if (length % 16) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    const unsigned char * end_addr = input + length;
    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;
    uint32_t *u32_iv = (uint32_t *)iv;

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    ret = aes_hw_setkey(ctx->key, ctx->keybits);
    if (ret != 0) {
        goto exit;
    }

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

    unsigned char last_input_block[16];

    while(in < (uint32_t*)end_addr)
    {
        memcpy(last_input_block, in, 16);
        LSCRYPT->DATA3 = __builtin_bswap32(*in++);
        LSCRYPT->DATA2 = __builtin_bswap32(*in++);
        LSCRYPT->DATA1 = __builtin_bswap32(*in++);
        LSCRYPT->DATA0 = __builtin_bswap32(*in++);
        REG_FIELD_WR(LSCRYPT->CR, CRYPT_GO, 1);
        if (aes_hw_wait_done() != 0) {
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            goto exit;
        }
        LSCRYPT->CR &= ~CRYPT_IVREN_MASK;
        LSCRYPT->ICFR = CRYPT_AESIF_MASK;
        *out++ = __builtin_bswap32(LSCRYPT->RES3);
        *out++ = __builtin_bswap32(LSCRYPT->RES2);
        *out++ = __builtin_bswap32(LSCRYPT->RES1);
        *out++ = __builtin_bswap32(LSCRYPT->RES0);
    }

    /* Write back updated IV to caller's iv buffer.
     * CBC encrypt: IV = last ciphertext output block.
     * CBC decrypt: IV = last ciphertext input block. */
    if (mode == MBEDTLS_AES_DECRYPT) {
        memcpy(iv, last_input_block, 16);
    } else {
        memcpy(iv, (unsigned char *)(out - 4), 16);
    }

exit:
    k_mutex_unlock(&aes_hw_mutex);
    return ret;
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

    if (ctx == NULL || iv_off == NULL || iv == NULL ||
        input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    n = *iv_off;

    if (n > 15) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    if (mode == MBEDTLS_AES_DECRYPT) {
        while (length--) {
            if (n == 0) {
                ret = aes_crypt_ecb_raw(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
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
                ret = aes_crypt_ecb_raw(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
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
    k_mutex_unlock(&aes_hw_mutex);
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

    if (ctx == NULL || iv == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    while (length--) {
        memcpy(ov, iv, 16);
        ret = aes_crypt_ecb_raw(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
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
    k_mutex_unlock(&aes_hw_mutex);
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

    if (ctx == NULL || iv_off == NULL || iv == NULL ||
        input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    n = *iv_off;

    if (n > 15) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    while (length--) {
        if (n == 0) {
            ret = aes_crypt_ecb_raw(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            if (ret != 0) {
                goto exit;
            }
        }
        *output++ =  *input++ ^ iv[n];

        n = (n + 1) & 0x0F;
    }

    *iv_off = n;

exit:
    k_mutex_unlock(&aes_hw_mutex);
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
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i = 0;
    size_t offset;

    if (ctx == NULL || nc_off == NULL || nonce_counter == NULL ||
        stream_block == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    offset = *nc_off;

    if (offset > 0x0F) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    /* 1. Resume from a partially-consumed keystream block left by a previous
     * call. nonce_counter already points past this block, so no new keystream
     * is generated here. */
    if (offset != 0) {
        size_t n = 16 - offset;
        if (n > length) {
            n = length;
        }
        mbedtls_xor(&output[i], &input[i], &stream_block[offset], n);
        i += n;
        offset = (offset + n) % 16;
    }

    /* 2. Whole 16-byte blocks via the hardware CTR engine. */
    size_t full_blocks = (length - i) / 16;
    if (full_blocks > 0) {
        uint32_t *in = (uint32_t *)(input + i);
        uint32_t *out = (uint32_t *)(output + i);
        uint32_t *u32_counter = (uint32_t *)nonce_counter;

        ret = aes_hw_setkey(ctx->key, ctx->keybits);
        if (ret != 0) {
            goto exit;
        }

        aes_config(false, true, false, false, false, 0x0, 0x2);

        LSCRYPT->IVR3 = __builtin_bswap32(*u32_counter++);
        LSCRYPT->IVR2 = __builtin_bswap32(*u32_counter++);
        LSCRYPT->IVR1 = __builtin_bswap32(*u32_counter++);
        LSCRYPT->IVR0 = __builtin_bswap32(*u32_counter++);

        for (size_t b = 0; b < full_blocks; b++) {
            LSCRYPT->DATA3 = __builtin_bswap32(*in++);
            LSCRYPT->DATA2 = __builtin_bswap32(*in++);
            LSCRYPT->DATA1 = __builtin_bswap32(*in++);
            LSCRYPT->DATA0 = __builtin_bswap32(*in++);
            REG_FIELD_WR(LSCRYPT->CR,CRYPT_GO,1);
            ret = aes_hw_wait_done();
            if (ret != 0) {
                goto exit;
            }
            LSCRYPT->ICFR = CRYPT_AESIF_MASK;
            *out++ = __builtin_bswap32(LSCRYPT->RES3);
            *out++ = __builtin_bswap32(LSCRYPT->RES2);
            *out++ = __builtin_bswap32(LSCRYPT->RES1);
            *out++ = __builtin_bswap32(LSCRYPT->RES0);
        }

        i += full_blocks * 16;

        /* The hardware auto-incremented its internal counter; mirror that in
         * the caller's nonce_counter so the next call resumes correctly. */
        for (size_t b = 0; b < full_blocks; b++) {
            mbedtls_ctr_increment_counter(nonce_counter);
        }
    }

    /* 3. Tail bytes that don't fill a whole block: generate one keystream
     * block and keep the unused part in stream_block for the next call. */
    if (i < length) {
        ret = aes_crypt_ecb_raw(ctx, MBEDTLS_AES_ENCRYPT,
                                nonce_counter, stream_block);
        if (ret != 0) {
            goto exit;
        }
        mbedtls_ctr_increment_counter(nonce_counter);

        size_t n = length - i;
        mbedtls_xor(&output[i], &input[i], stream_block, n);
        i += n;
        offset = n;
    }

    /* Capture offset for future resumption. */
    *nc_off = offset;

    ret = 0;

exit:
    k_mutex_unlock(&aes_hw_mutex);
    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
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

    ret = mbedtls_aes_setkey_enc(&ctx->crypt, key1, key1bits);
    if (ret != 0) {
        return ret;
    }

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

    k_mutex_lock(&aes_hw_mutex, K_FOREVER);

    /* Compute the tweak. */
    ret = aes_crypt_ecb_raw(&ctx->tweak, MBEDTLS_AES_ENCRYPT,
                            data_unit, tweak);
    if (ret != 0) {
        goto exit;
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

        ret = aes_crypt_ecb_raw(&ctx->crypt, mode, tmp, tmp);
        if (ret != 0) {
            goto exit;
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

        ret = aes_crypt_ecb_raw(&ctx->crypt, mode, tmp, tmp);
        if (ret != 0) {
            goto exit;
        }

        /* Write the result back to the previous block, overriding the previous
         * output we copied. */
        mbedtls_xor(prev_output, tmp, t, 16);
    }

    ret = 0;

exit:
    k_mutex_unlock(&aes_hw_mutex);
    return ret;
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