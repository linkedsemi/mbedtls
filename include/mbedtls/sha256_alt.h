#ifndef SHA256_ALT_H
#define SHA256_ALT_H
#include <stdint.h>
#include "mbedtls/private_access.h"

#if defined(CONFIG_MBEDTLS_HARDWARE_SHA224_SHA256_SM3_LINKEDSEMI)
typedef struct mbedtls_sha256_context {
    bool start_calc_symbol;
}
mbedtls_sha256_context;

/**
 * \brief          This function initializes a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to initialize. This must not be \c NULL.
 */
void mbedtls_sm3_init(mbedtls_sha256_context *ctx);

/**
 * \brief          This function starts a SM3 checksum calculation.
 *
 * \param ctx      The context to use. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_starts(mbedtls_sha256_context *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 *
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen);

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SM3 checksum result.
 *                 This must be a writable buffer of length \c 32 bytes for SM3.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sm3_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output);

/**
 * \brief          This function clears a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to clear. This may be \c NULL, in which
 *                 case this function returns immediately. If it is not \c NULL,
 *                 it must point to an initialized SHA-256 context.
 */
void mbedtls_sm3_free(mbedtls_sha256_context *ctx);

#endif /* CONFIG_MBEDTLS_HARDWARE_SHA224_SHA256_SM3_LINKEDSEMI */

#endif /* sha256_alt.h */