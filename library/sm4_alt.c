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

/* The e906 is little-endian, so a direct word load/store from the byte arrays
 * below already matches the hardware key/data order. */
static void sm4_hw_setkey(const uint8_t *key)
{
    LSSM4->SM4_KEY0 = *(const uint32_t *)key;
    LSSM4->SM4_KEY1 = *(const uint32_t *)(key + 4);
    LSSM4->SM4_KEY2 = *(const uint32_t *)(key + 8);
    LSSM4->SM4_KEY3 = *(const uint32_t *)(key + 12);
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
        LSSM4->CALC_WRD = *(const uint32_t *)in;
        LSSM4->CALC_WRD = *(const uint32_t *)(in + 4);
        LSSM4->CALC_WRD = *(const uint32_t *)(in + 8);
        LSSM4->CALC_WRD = *(const uint32_t *)(in + 12);
        LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
    }

    while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
    LSSM4->INTR_CLR = SM4_INTR_END_MASK;
    *(uint32_t *)out = LSSM4->CALC_RSLT0;
    *(uint32_t *)(out + 4) = LSSM4->CALC_RSLT1;
    *(uint32_t *)(out + 8) = LSSM4->CALC_RSLT2;
    *(uint32_t *)(out + 12) = LSSM4->CALC_RSLT3;
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

    /* SM4_CALC_LEN is a 14-bit field: at most 16384 blocks (256 KiB) per call. */
    if (length / SM4_BLOCK_SIZE > 16384) {
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

/* ---- SM4 GCM (Galois/Counter Mode) ----
 *
 * One-shot authenticated encryption/decryption mirroring the mbedtls GCM API
 * (crypt_and_tag / auth_decrypt). E_K runs in hardware via
 * sm4_hw_encrypt_block; GHASH is software, ported from the reference
 * ls_hal_sm4.c. Only the standard 12-byte nonce is supported. */

#define BSWAP_64(x)                                                  \
    ((((uint64_t)(x) & 0x00000000000000ffULL) << 56) |               \
     (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) |               \
     (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) |               \
     (((uint64_t)(x) & 0x00000000ff000000ULL) << 8)  |               \
     (((uint64_t)(x) & 0x000000ff00000000ULL) >> 8)  |               \
     (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) |               \
     (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) |               \
     (((uint64_t)(x) & 0xff00000000000000ULL) >> 56))

static void xor_bytes(unsigned char *dst, const unsigned char *a,
                      const unsigned char *b, size_t n)
{
    while (n--) {
        *dst++ = *a++ ^ *b++;
    }
}

/* GHASH core multiply: x = x * y in GF(2^128). Both operands are stored as two
 * 64-bit words in big-endian order (word[0] is the most-significant 64 bits). */
static void gmult(uint64_t x[2], const uint64_t y[2])
{
    uint64_t z[2] = { 0, 0 };
    uint64_t v[2] = { x[0], x[1] };

    for (int i = 0; i < 2; i++) {
        uint64_t y_tmp = y[i];
        for (int j = 0; j < 64; j++) {
            uint64_t mask = 0 - (y_tmp >> 63);
            z[0] ^= v[0] & mask;
            z[1] ^= v[1] & mask;
            uint64_t v1 = (0 - (v[1] & 1)) & 0xe100000000000000ULL;
            v[1] >>= 1;
            v[1] |= v[0] << 63;
            v[0] >>= 1;
            v[0] ^= v1;
            y_tmp <<= 1;
        }
    }

    x[0] = z[0];
    x[1] = z[1];
}

/* One-shot GHASH over AAD (a) and ciphertext (c); s receives the 16-byte
 * GHASH output. big_h is E_K(0) held in big-endian u64 form. */
static void ghash(const uint64_t big_h[2],
                  const unsigned char *a, size_t a_size,
                  const unsigned char *c, size_t c_size,
                  unsigned char *s)
{
    uint64_t x[2] = { 0, 0 };
    uint64_t block[2];
    size_t n;

    n = a_size / 16;
    while (n--) {
        memcpy(block, a, 16);
        x[0] ^= BSWAP_64(block[0]);
        x[1] ^= BSWAP_64(block[1]);
        gmult(x, big_h);
        a += 16;
    }
    n = a_size % 16;
    if (n) {
        memset(block, 0, 16);
        memcpy(block, a, n);
        x[0] ^= BSWAP_64(block[0]);
        x[1] ^= BSWAP_64(block[1]);
        gmult(x, big_h);
    }

    n = c_size / 16;
    while (n--) {
        memcpy(block, c, 16);
        x[0] ^= BSWAP_64(block[0]);
        x[1] ^= BSWAP_64(block[1]);
        gmult(x, big_h);
        c += 16;
    }
    n = c_size % 16;
    if (n) {
        memset(block, 0, 16);
        memcpy(block, c, n);
        x[0] ^= BSWAP_64(block[0]);
        x[1] ^= BSWAP_64(block[1]);
        gmult(x, big_h);
    }

    /* Lengths of A and C in bits, as big-endian 64-bit values. */
    x[0] ^= (uint64_t)a_size * 8;
    x[1] ^= (uint64_t)c_size * 8;
    gmult(x, big_h);

    x[0] = BSWAP_64(x[0]);
    x[1] = BSWAP_64(x[1]);
    memcpy(s, x, 16);
}

/* Increment the 32-bit GCM counter (last four bytes, big-endian). */
static void gcm_incr(unsigned char y[16])
{
    uint32_t x = ((uint32_t)y[12] << 24) | ((uint32_t)y[13] << 16) |
                 ((uint32_t)y[14] << 8) | (uint32_t)y[15];
    x++;
    y[12] = (unsigned char)(x >> 24);
    y[13] = (unsigned char)(x >> 16);
    y[14] = (unsigned char)(x >> 8);
    y[15] = (unsigned char)x;
}

void mbedtls_sm4_gcm_init(mbedtls_sm4_gcm_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(mbedtls_sm4_gcm_context));
}

void mbedtls_sm4_gcm_free(mbedtls_sm4_gcm_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sm4_gcm_context));
}

int mbedtls_sm4_gcm_setkey(mbedtls_sm4_gcm_context *ctx, const unsigned char *key)
{
    unsigned char h[16];
    uint64_t big_h[2];

    if (ctx == NULL || key == NULL) {
        return -EINVAL;
    }

    memcpy(ctx->cipher.key, key, SM4_KEY_SIZE);

    /* H = E_K(0^128), the GHASH key, kept in big-endian form for gmult(). */
    memset(h, 0, sizeof(h));
    k_mutex_lock(&sm4_hw_mutex, K_FOREVER);
    sm4_hw_setkey(ctx->cipher.key);
    sm4_hw_encrypt_block(h, h);
    k_mutex_unlock(&sm4_hw_mutex);

    memcpy(big_h, h, 16);
    ctx->H[0] = BSWAP_64(big_h[0]);
    ctx->H[1] = BSWAP_64(big_h[1]);

    return 0;
}

int mbedtls_sm4_gcm_crypt_and_tag(mbedtls_sm4_gcm_context *ctx, int mode,
                                  size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *add, size_t add_len,
                                  const unsigned char *input, unsigned char *output,
                                  size_t tag_len, unsigned char *tag)
{
    unsigned char j0[16];
    unsigned char ej0[16];
    unsigned char s[16];
    unsigned char counter[16];
    unsigned char keystream[16];
    const unsigned char *in = input;
    unsigned char *out = output;
    size_t left;

    if (ctx == NULL || iv == NULL || tag == NULL) {
        return -EINVAL;
    }
    if ((input == NULL || output == NULL) && length > 0) {
        return -EINVAL;
    }
    if (add == NULL && add_len > 0) {
        return -EINVAL;
    }
    if (tag_len < 4 || tag_len > 16) {
        return -EINVAL;
    }
    if (iv_len != 12) {
        return -EINVAL;
    }

    /* J0 = IV || 0^31 || 1. */
    memcpy(j0, iv, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    memcpy(counter, j0, 16);

    /* GHASH runs over the ciphertext. For decrypt that is `input` and must be
     * hashed BEFORE GCTR overwrites it (in-place input==output case); for
     * encrypt it is `output`, only available after GCTR. */
    if (mode == MBEDTLS_SM4_GCM_DECRYPT) {
        ghash(ctx->H, add, add_len, input, length, s);
    }

    k_mutex_lock(&sm4_hw_mutex, K_FOREVER);
    sm4_hw_setkey(ctx->cipher.key);

    /* E_K(J0) is the tag mask. */
    sm4_hw_encrypt_block(j0, ej0);

    /* GCTR: out = keystream ^ in. */
    left = length;
    while (left >= 16) {
        gcm_incr(counter);
        sm4_hw_encrypt_block(counter, keystream);
        xor_bytes(out, in, keystream, 16);
        in += 16;
        out += 16;
        left -= 16;
    }
    if (left) {
        gcm_incr(counter);
        sm4_hw_encrypt_block(counter, keystream);
        xor_bytes(out, in, keystream, left);
    }

    k_mutex_unlock(&sm4_hw_mutex);

    if (mode == MBEDTLS_SM4_GCM_ENCRYPT) {
        ghash(ctx->H, add, add_len, output, length, s);
    }

    /* tag = S ^ E_K(J0). */
    for (size_t i = 0; i < tag_len; i++) {
        tag[i] = s[i] ^ ej0[i];
    }

    return 0;
}

static int sm4_ct_memcmp(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    while (n--) {
        diff |= (unsigned char)(*a++ ^ *b++);
    }
    return diff;
}

int mbedtls_sm4_gcm_auth_decrypt(mbedtls_sm4_gcm_context *ctx, size_t length,
                                 const unsigned char *iv, size_t iv_len,
                                 const unsigned char *add, size_t add_len,
                                 const unsigned char *tag, size_t tag_len,
                                 const unsigned char *input, unsigned char *output)
{
    int ret;
    unsigned char check_tag[16];

    if ((ret = mbedtls_sm4_gcm_crypt_and_tag(ctx, MBEDTLS_SM4_GCM_DECRYPT, length,
                                             iv, iv_len, add, add_len,
                                             input, output, tag_len, check_tag)) != 0) {
        return ret;
    }

    if (sm4_ct_memcmp(tag, check_tag, tag_len) != 0) {
        mbedtls_platform_zeroize(output, length);
        return -EBADMSG;
    }

    return 0;
}

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT */