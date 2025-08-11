#include <assert.h>
#include <ls_hal_sha.h>
#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"

#if defined(CONFIG_MBEDTLS_SHA256_LINKEDSEMI)
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha256_context* ls_sha_ctx = NULL;

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
    mbedtls_zephyr_threading_init();
    mbedtls_mutex_init(&doneLock);
    HAL_LSSHA_Init();
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
#if defined(MBEDTLS_SHA224_C) && defined(MBEDTLS_SHA256_C)
    if (is224 != 0 && is224 != 1) {
        return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
    }
#elif defined(MBEDTLS_SHA256_C)
    if (is224 != 0) {
        return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
    }
#else /* defined MBEDTLS_SHA224_C only */
    if (is224 == 0) {
        return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
    }
#endif

    if(is224)
    {
        HAL_LSSHA_SHA224_Init();
    }else{
        HAL_LSSHA_SHA256_Init();
    }

    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *lsCtx,
                          const unsigned char *input,
                          size_t ilen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (!lsCtx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = lsCtx;
        lsCtx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == lsCtx);

    ret = HAL_LSSHA_Update(input, ilen);
    return ret;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *lsCtx,
                          unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    assert(ls_sha_ctx == lsCtx);
    ret = HAL_LSSHA_Final(output);
    ls_sha_ctx = NULL;
    lsCtx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}
#endif /* CONFIG_MBEDTLS_SHA256_LINKEDSEMI */