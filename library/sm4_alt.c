#include "mbedtls/platform_util.h"
#include <errno.h>
#include <string.h>
#include "mbedtls/sm4_alt.h"
#include <zephyr/kernel.h>
#include "ls_msp_sm4.h"
#include "field_manipulate.h"
#include "reg_sm4_type.h"

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT)

/* Serialize access to the shared LSSM4 register bank. The SM4 key is expanded
 * into the hardware round-key registers and stays there until the next key is
 * loaded, so every operation must hold this lock across the whole key-reload +
 * calculate sequence. */
static K_MUTEX_DEFINE(sm4_hw_mutex);

/* Little-endian byte <-> word helpers, matching the hardware key/data order. */
static uint32_t u8tou32(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void u32tou8(uint32_t in, uint8_t *out)
{
    *out++ = (uint8_t)in;
    *out++ = (uint8_t)(in >> 8);
    *out++ = (uint8_t)(in >> 16);
    *out++ = (uint8_t)(in >> 24);
}

static void sm4_hw_setkey(const uint8_t *key)
{
    LSSM4->SM4_KEY0 = u8tou32(key);
    LSSM4->SM4_KEY1 = u8tou32(key + 4);
    LSSM4->SM4_KEY2 = u8tou32(key + 8);
    LSSM4->SM4_KEY3 = u8tou32(key + 12);
    LSSM4->SM4_START = SM4_KEY_START_MASK;
    while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_KEY_END) == 0);
    LSSM4->INTR_CLR = SM4_KEY_END_MASK;
}

/* Single-block SM4 encrypt (16 bytes in -> 16 bytes out). Reimplements the
 * HAL's sm4_data_length_inout_config + sm4_calculate for one block, but with
 * local state instead of the HAL's static globals. Used by the CTR path to
 * produce one keystream block (the counter block is always encrypted). The
 * caller must hold sm4_hw_mutex and have already loaded the key. */
static void sm4_hw_encrypt_block(const uint8_t *in, uint8_t *out)
{
    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, 0);
    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_DEC, 0);

    LSSM4->SM4_START = SM4_CALC_START_MASK;

    if (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1) {
        LSSM4->CALC_WRD = u8tou32(in);
        LSSM4->CALC_WRD = u8tou32(in + 4);
        LSSM4->CALC_WRD = u8tou32(in + 8);
        LSSM4->CALC_WRD = u8tou32(in + 12);
        LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
    }

    while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
    LSSM4->INTR_CLR = SM4_INTR_END_MASK;
    u32tou8(LSSM4->CALC_RSLT0, out);
    u32tou8(LSSM4->CALC_RSLT1, out + 4);
    u32tou8(LSSM4->CALC_RSLT2, out + 8);
    u32tou8(LSSM4->CALC_RSLT3, out + 12);
}

/* Big-endian 16-byte counter increment (SM4 CTR convention). */
static void sm4_ctr_increment(uint8_t counter[16])
{
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

void mbedtls_sm4_init(mbedtls_sm4_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(mbedtls_sm4_context));
}

void mbedtls_sm4_free(mbedtls_sm4_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sm4_context));
}

int mbedtls_sm4_setkey_enc(mbedtls_sm4_context *ctx, const unsigned char *key)
{
    if (ctx == NULL || key == NULL) {
        return -EINVAL;
    }
    memcpy(ctx->key, key, SM4_KEY_SIZE);
    return 0;
}

int mbedtls_sm4_setkey_dec(mbedtls_sm4_context *ctx, const unsigned char *key)
{
    return mbedtls_sm4_setkey_enc(ctx, key);
}

int mbedtls_sm4_crypt_ecb(mbedtls_sm4_context *ctx, int mode, size_t length,
                          const unsigned char *input, unsigned char *output)
{
    if (ctx == NULL || input == NULL || output == NULL) {
        return -EINVAL;
    }

    if (length == 0 || length % SM4_BLOCK_SIZE != 0) {
        return -EINVAL;
    }

    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    k_mutex_lock(&sm4_hw_mutex, K_FOREVER);

    /* Restore this context's key — another context may have overwritten the
     * shared hardware round keys since the last setkey call. */
    sm4_hw_setkey(ctx->key);

    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, length / SM4_BLOCK_SIZE - 1);
    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_DEC, mode == MBEDTLS_SM4_DECRYPT ? 1 : 0);

    LSSM4->SM4_START = SM4_CALC_START_MASK;

    if (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1) {
        LSSM4->CALC_WRD = *in++;
        LSSM4->CALC_WRD = *in++;
        LSSM4->CALC_WRD = *in++;
        LSSM4->CALC_WRD = *in++;
        LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
    }
    do {
        if (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1) {
            *out++ = LSSM4->CALC_RSLT0;
            *out++ = LSSM4->CALC_RSLT1;
            *out++ = LSSM4->CALC_RSLT2;
            *out++ = LSSM4->CALC_RSLT3;
            LSSM4->CALC_WRD = *in++;
            LSSM4->CALC_WRD = *in++;
            LSSM4->CALC_WRD = *in++;
            LSSM4->CALC_WRD = *in++;
            LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
        }
    } while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
    LSSM4->INTR_CLR = SM4_INTR_END_MASK;
    *out++ = LSSM4->CALC_RSLT0;
    *out++ = LSSM4->CALC_RSLT1;
    *out++ = LSSM4->CALC_RSLT2;
    *out++ = LSSM4->CALC_RSLT3;

    k_mutex_unlock(&sm4_hw_mutex);
    return 0;
}

int mbedtls_sm4_crypt_ctr(mbedtls_sm4_context *ctx, size_t length, size_t *nc_off,
                          unsigned char nonce_counter[16], unsigned char stream_block[16],
                          const unsigned char *input, unsigned char *output)
{
    size_t n;

    if (ctx == NULL || nc_off == NULL || nonce_counter == NULL ||
        stream_block == NULL || input == NULL || output == NULL) {
        return -EINVAL;
    }

    n = *nc_off;

    k_mutex_lock(&sm4_hw_mutex, K_FOREVER);

    /* Restore this context's key — another context may have overwritten the
     * shared hardware round keys since the last setkey call. */
    sm4_hw_setkey(ctx->key);

    while (length--) {
        if (n == 0) {
            /* CTR always encrypts the counter block, even when decrypting. */
            sm4_hw_encrypt_block(nonce_counter, stream_block);
            sm4_ctr_increment(nonce_counter);
        }

        *output++ = (unsigned char)(*input++ ^ stream_block[n]);
        n = (n + 1) & 0x0F;
    }

    *nc_off = n;

    k_mutex_unlock(&sm4_hw_mutex);
    return 0;
}

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT */