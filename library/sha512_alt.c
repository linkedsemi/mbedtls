#include <assert.h>
#include <string.h>
#include "mbedtls/sha512.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"

#if defined(CONFIG_MBEDTLS_SHA512_LINKEDSEMI)
#include <ls_hal_sha512.h>
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha512_context* ls_sha_ctx = NULL;

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
    mbedtls_zephyr_threading_init();
    mbedtls_mutex_init(&doneLock);
    HAL_SHA512_Init();
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha512_context));
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
#if defined(MBEDTLS_SHA384_C) && defined(MBEDTLS_SHA512_C)
    if (is384 != 0 && is384 != 1) {
        return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
    }
#elif defined(MBEDTLS_SHA512_C)
    if (is384 != 0) {
        return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
    }
#else /* defined MBEDTLS_SHA384_C only */
    if (is384 == 0) {
        return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
    }
#endif

    if (is384) 
    {
        HAL_SHA384_SHA384_Init();
    } else {
        HAL_SHA512_SHA512_Init();
    }

    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *lsCtx,
                          const unsigned char *input,
                          size_t ilen)
{
    if (!lsCtx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = lsCtx;
        lsCtx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == lsCtx);
    HAL_SHA512_SHA512_Update((uint32_t *)input, ilen);
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *lsCtx,
                          unsigned char *output)
{
    assert(ls_sha_ctx == lsCtx);
    HAL_SHA512_SHA512_Final(output);
    ls_sha_ctx = NULL;
    lsCtx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return 0;
}
#endif /* CONFIG_MBEDTLS_SHA512_LINKEDSEMI */