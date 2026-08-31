#ifndef SHA256_ALT_H
#define SHA256_ALT_H
#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/private_access.h"

#if defined(MBEDTLS_SHA256_ALT)
#include "otbn_hash.h"

typedef struct mbedtls_sha256_context {
    bool start_calc_symbol;
    bool is224;
    otbn_hash_ctx_t otbn;

    uint32_t hw_current_word;
    uint8_t  hw_current_block_bytes;
    uint64_t hw_total_length;
    bool     hw_block_needs_start;
}
mbedtls_sha256_context;

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src);

void mbedtls_sha256_init_dma(mbedtls_sha256_context *ctx);

int mbedtls_sha256_starts_dma(mbedtls_sha256_context *ctx, int is224);

int mbedtls_sha256_finish_dma(mbedtls_sha256_context *ctx,
                          unsigned char *output);

#endif

#endif /* sha256_alt.h */