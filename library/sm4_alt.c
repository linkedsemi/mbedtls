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

    /* mbedtls CTR contract: nc_off is an index into stream_block, so values
     * above 15 would read past it (AES alt rejects them the same way). */
    if (n > 0x0F) {
        return -EINVAL;
    }

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
 * sm4_hw_encrypt_block; GHASH is a software 4-bit-table implementation ported
 * from wolfSSL's GCM_TABLE_4BIT (the fastest software GHASH on RV32/e906).
 * Only the standard 12-byte nonce is supported. */

static void xor_bytes(unsigned char *dst, const unsigned char *a,
                      const unsigned char *b, size_t n)
{
    while (n--) {
        *dst++ = *a++ ^ *b++;
    }
}

/* Remainder table for the 4-bit multiply, indexed by the top nibble (little-
 * endian word16 form; the in-memory byte order matches the big-endian block
 * convention used throughout). */
static const uint16_t R[32] = {
    0x0000, 0x201c, 0x4038, 0x6024,
    0x8070, 0xa06c, 0xc048, 0xe054,
    0x00e1, 0x20fd, 0x40d9, 0x60c5,
    0x8091, 0xa08d, 0xc0a9, 0xe0b5,

    0x0000, 0xc201, 0x8403, 0x4602,
    0x0807, 0xca06, 0x8c04, 0x4e05,
    0x100e, 0xd20f, 0x940d, 0x560c,
    0x1809, 0xda08, 0x9c0a, 0x5e0b,
};

/* x >>= 1 in GF(2^128). Byte 0 is the most-significant byte, so the 0xE1
 * reduction term is XORed into byte 0 when the value was odd. */
static void RIGHTSHIFTX(unsigned char *x)
{
    int i;
    int carryIn = 0;
    unsigned char borrow = (unsigned char)((0x00U - (x[15] & 0x01U)) & 0xE1U);

    for (i = 0; i < 16; i++) {
        int carryOut = (x[i] & 0x01) << 7;
        x[i] = (unsigned char)((x[i] >> 1) | carryIn);
        carryIn = carryOut;
    }
    x[0] ^= borrow;
}

/* z8 >>= 4 (nibble right-shift), used to build the pre-rotated table half. */
static void Shift4_M0(unsigned char *r8, const unsigned char *z8)
{
    int i;
    for (i = 15; i > 0; i--) {
        r8[i] = (unsigned char)((z8[i - 1] << 4) | (z8[i] >> 4));
    }
    r8[0] = (unsigned char)(z8[0] >> 4);
}

/* buf[0..7] = sz * 8 as a 64-bit big-endian value. */
static void FlattenSzInBits(unsigned char *buf, uint32_t sz)
{
    uint32_t szHi = sz >> 29;
    sz <<= 3;

    buf[0] = (unsigned char)(szHi >> 24);
    buf[1] = (unsigned char)(szHi >> 16);
    buf[2] = (unsigned char)(szHi >> 8);
    buf[3] = (unsigned char)szHi;
    buf[4] = (unsigned char)(sz >> 24);
    buf[5] = (unsigned char)(sz >> 16);
    buf[6] = (unsigned char)(sz >> 8);
    buf[7] = (unsigned char)sz;
}

/* Build the 32-entry (16 normal + 16 pre-rotated) 4-bit multiply table from
 * H = E_K(0^128) held in raw big-endian byte order. */
static void GenerateM0(unsigned char m[32][16], const unsigned char *H)
{
    int i;

    /* 0 times -> 0x0 */
    memset(m[0x0], 0, 16);
    /* 1 times -> 0x8 */
    memcpy(m[0x8], H, 16);
    /* 2 times -> 0x4 */
    memcpy(m[0x4], m[0x8], 16);
    RIGHTSHIFTX(m[0x4]);
    /* 4 times -> 0x2 */
    memcpy(m[0x2], m[0x4], 16);
    RIGHTSHIFTX(m[0x2]);
    /* 8 times -> 0x1 */
    memcpy(m[0x1], m[0x2], 16);
    RIGHTSHIFTX(m[0x1]);

    memcpy(m[0x3], m[0x2], 16); xor_bytes(m[0x3], m[0x3], m[0x1], 16);
    memcpy(m[0x5], m[0x4], 16); xor_bytes(m[0x5], m[0x5], m[0x1], 16);
    memcpy(m[0x6], m[0x4], 16); xor_bytes(m[0x6], m[0x6], m[0x2], 16);
    memcpy(m[0x7], m[0x4], 16); xor_bytes(m[0x7], m[0x7], m[0x3], 16);
    memcpy(m[0x9], m[0x8], 16); xor_bytes(m[0x9], m[0x9], m[0x1], 16);
    memcpy(m[0xa], m[0x8], 16); xor_bytes(m[0xa], m[0xa], m[0x2], 16);
    memcpy(m[0xb], m[0x8], 16); xor_bytes(m[0xb], m[0xb], m[0x3], 16);
    memcpy(m[0xc], m[0x8], 16); xor_bytes(m[0xc], m[0xc], m[0x4], 16);
    memcpy(m[0xd], m[0x8], 16); xor_bytes(m[0xd], m[0xd], m[0x5], 16);
    memcpy(m[0xe], m[0x8], 16); xor_bytes(m[0xe], m[0xe], m[0x6], 16);
    memcpy(m[0xf], m[0x8], 16); xor_bytes(m[0xf], m[0xf], m[0x7], 16);

    for (i = 0; i < 16; i++) {
        Shift4_M0(m[16 + i], m[i]);
    }
}

/* x = x * H in GF(2^128) using the 4-bit table. 32-bit word-rotate variant,
 * the fastest software form on RV32. */
static void GMULT(unsigned char *x, unsigned char m[32][16])
{
    int i;
    uint32_t z8[4] = { 0, 0, 0, 0 };
    unsigned char a;
    uint32_t *x8 = (uint32_t *)x;
    uint32_t *m8;
    unsigned char xi;
    uint32_t n7, n6, n5, n4, n3, n2, n1, n0;

    for (i = 15; i > 0; i--) {
        xi = x[i];

        /* XOR in (msn * H) */
        m8 = (uint32_t *)m[xi & 0xf];
        z8[0] ^= m8[0]; z8[1] ^= m8[1]; z8[2] ^= m8[2]; z8[3] ^= m8[3];

        /* Cache top byte for remainder calculations - lost in rotate. */
        a = (unsigned char)(z8[3] >> 24);

        /* Rotate Z by 8 bits. */
        z8[3] = (z8[2] >> 24) | (z8[3] << 8);
        z8[2] = (z8[1] >> 24) | (z8[2] << 8);
        z8[1] = (z8[0] >> 24) | (z8[1] << 8);
        z8[0] <<= 8;

        /* XOR in (msn * remainder) [pre-rotated by 4 bits]. */
        z8[0] ^= (uint32_t)R[16 + (a & 0xf)];

        xi >>= 4;
        /* XOR in next significant nibble (XORed with H) * remainder. */
        m8 = (uint32_t *)m[xi];
        a ^= (unsigned char)(m8[3] >> 20);
        z8[0] ^= (uint32_t)R[a >> 4];

        /* XOR in (next significant nibble * H) [pre-rotated by 4 bits]. */
        m8 = (uint32_t *)m[16 + xi];
        z8[0] ^= m8[0]; z8[1] ^= m8[1];
        z8[2] ^= m8[2]; z8[3] ^= m8[3];
    }

    xi = x[0];

    /* XOR in most significant nibble * H. */
    m8 = (uint32_t *)m[xi & 0xf];
    z8[0] ^= m8[0]; z8[1] ^= m8[1]; z8[2] ^= m8[2]; z8[3] ^= m8[3];

    /* Cache top byte for remainder calculations - lost in rotate. */
    a = (unsigned char)((z8[3] >> 24) & 0xf);

    /* Rotate z by 4 bits. */
    n7 = z8[3] & 0xf0f0f0f0U;
    n6 = z8[3] & 0x0f0f0f0fU;
    n5 = z8[2] & 0xf0f0f0f0U;
    n4 = z8[2] & 0x0f0f0f0fU;
    n3 = z8[1] & 0xf0f0f0f0U;
    n2 = z8[1] & 0x0f0f0f0fU;
    n1 = z8[0] & 0xf0f0f0f0U;
    n0 = z8[0] & 0x0f0f0f0fU;
    z8[3] = (n7 >> 4) | (n6 << 12) | (n4 >> 20);
    z8[2] = (n5 >> 4) | (n4 << 12) | (n2 >> 20);
    z8[1] = (n3 >> 4) | (n2 << 12) | (n0 >> 20);
    z8[0] = (n1 >> 4) | (n0 << 12);

    /* XOR in most significant nibble * remainder. */
    z8[0] ^= (uint32_t)R[a];
    /* XOR in next significant nibble * H. */
    m8 = (uint32_t *)m[xi >> 4];
    z8[0] ^= m8[0]; z8[1] ^= m8[1]; z8[2] ^= m8[2]; z8[3] ^= m8[3];

    /* Write back result. */
    x8[0] = z8[0]; x8[1] = z8[1]; x8[2] = z8[2]; x8[3] = z8[3];
}

/* One-shot GHASH over AAD (a) and ciphertext (c); s receives the 16-byte
 * GHASH output. m is the per-key 4-bit multiply table. */
static void ghash(unsigned char m[32][16],
                  const unsigned char *a, size_t a_size,
                  const unsigned char *c, size_t c_size,
                  unsigned char *s)
{
    unsigned char x[16];
    unsigned char scratch[16];
    size_t blocks, partial;

    memset(x, 0, 16);

    /* Hash in A, the Additional Authentication Data. */
    if (a_size != 0 && a != NULL) {
        blocks = a_size / 16;
        partial = a_size % 16;
        while (blocks--) {
            xor_bytes(x, x, a, 16);
            GMULT(x, m);
            a += 16;
        }
        if (partial != 0) {
            memset(scratch, 0, 16);
            memcpy(scratch, a, partial);
            xor_bytes(x, x, scratch, 16);
            GMULT(x, m);
        }
    }

    /* Hash in C, the Ciphertext. */
    if (c_size != 0 && c != NULL) {
        blocks = c_size / 16;
        partial = c_size % 16;
        while (blocks--) {
            xor_bytes(x, x, c, 16);
            GMULT(x, m);
            c += 16;
        }
        if (partial != 0) {
            memset(scratch, 0, 16);
            memcpy(scratch, c, partial);
            xor_bytes(x, x, scratch, 16);
            GMULT(x, m);
        }
    }

    /* Hash in the lengths of A and C in bits. */
    FlattenSzInBits(&scratch[0], (uint32_t)a_size);
    FlattenSzInBits(&scratch[8], (uint32_t)c_size);
    xor_bytes(x, x, scratch, 16);
    GMULT(x, m);

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

    if (ctx == NULL || key == NULL) {
        return -EINVAL;
    }

    memcpy(ctx->cipher.key, key, SM4_KEY_SIZE);

    /* H = E_K(0^128), the GHASH key; expand it into the 4-bit multiply table. */
    memset(h, 0, sizeof(h));
    k_mutex_lock(&sm4_hw_mutex, K_FOREVER);
    sm4_hw_setkey(ctx->cipher.key);
    sm4_hw_encrypt_block(h, h);
    k_mutex_unlock(&sm4_hw_mutex);

    GenerateM0(ctx->M0, h);

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
        ghash(ctx->M0, add, add_len, input, length, s);
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
        ghash(ctx->M0, add, add_len, output, length, s);
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