#ifndef SM3_ALT_H
#define SM3_ALT_H
#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/private_access.h"
#include "otbn_hash.h"

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT) || defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)

typedef struct mbedtls_sm3_context {
    bool start_calc_symbol;
    bool is224;
    otbn_hash_ctx_t otbn;

    uint32_t hw_current_word;
    uint8_t  hw_current_block_bytes;
    uint64_t hw_total_length;
    bool     hw_block_needs_start;
}
mbedtls_sm3_context;

/**
 * \brief          This function initializes a SM3 context.
 *
 * \param ctx      The SM3 context to initialize. This must not be \c NULL.
 */
void mbedtls_sm3_init(mbedtls_sm3_context *ctx);

/**
 * \brief          This function starts a SM3 checksum calculation.
 *
 * \param ctx      The context to use. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_starts(mbedtls_sm3_context *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SM3 checksum calculation.
 *
 * \param ctx      The SM3 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen);

/**
 * \brief          This function finishes the SM3 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SM3 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SM3 checksum result.
 *                 This must be a writable buffer of length \c 32 bytes for SM3.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char *output);

/**
 * \brief          This function clears a SM3 context.
 *
 * \param ctx      The SM3 context to clear. This may be \c NULL, in which
 *                 case this function returns immediately. If it is not \c NULL,
 *                 it must point to an initialized SM3 context.
 */
void mbedtls_sm3_free(mbedtls_sm3_context *ctx);

void mbedtls_sm3_init_dma(mbedtls_sm3_context *ctx);

int mbedtls_sm3_starts_dma(mbedtls_sm3_context *ctx);

int mbedtls_sm3_update_dma(mbedtls_sm3_context *ctx,
                           const unsigned char *input,
                           size_t ilen);

int mbedtls_sm3_finish_dma(mbedtls_sm3_context *ctx,
                           unsigned char *output);

#endif

#endif /* sm3_alt.h */
