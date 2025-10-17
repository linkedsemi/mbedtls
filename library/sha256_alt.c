#include <assert.h>
#include <ls_hal_sha.h>
#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"

#if CONFIG_SOC_LSQSH
    #if CONFIG_SHA256_CLOCK_RESET
        #include "reg_sysc_sec_cpu.h"
    #endif
#endif

#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
#include "ls_hal_otbn_sha.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"
#include "platform.h"
void mbedtls_ls_otbn_moudle_init(void);
void mbedtls_ls_otbn_moudle_deinit(void);
static struct k_sem wait_complete;
void ls_otbn_mbedtls_update_callback(void (*func)(void*),void *param);

static void mbedtls_ls_otbn_sha256_handler()
{
    if (LSOTBN->INTR_STATE)
    {
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
        // k_sem_give(&wait_complete);

    }
}
#endif

#if defined(CONFIG_MBEDTLS_HARDWARE_SHA224_SHA256_SM3_LINKEDSEMI)
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha256_context* ls_sha_ctx = NULL;

void mbedtls_sm3_init(mbedtls_sha256_context *ctx)
{
    mbedtls_sha256_init(ctx);
}

int mbedtls_sm3_starts(mbedtls_sha256_context *ctx)
{
    HAL_LSSHA_SM3_Init();
    return 0;
}

int mbedtls_sm3_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return mbedtls_sha256_update(ctx, input, ilen);
}

int mbedtls_sm3_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    return mbedtls_sha256_finish(ctx, output);
}

void mbedtls_sm3_free(mbedtls_sha256_context *ctx)
{
    mbedtls_sha256_free(ctx);
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
    // mbedtls_zephyr_threading_init();
    mbedtls_mutex_init(&doneLock);
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    mbedtls_ls_otbn_moudle_init();
    k_sem_init(&wait_complete,0,1);
#else
    #if CONFIG_SOC_LS1010
        HAL_LSSHA_Init();
    #elif CONFIG_SOC_LSQSH
        #if CONFIG_SHA256_CLOCK_RESET
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_CALC_SHA_MASK;
        #endif
    #endif

#endif
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    mbedtls_ls_otbn_moudle_deinit();
    k_sem_reset(&wait_complete);
#endif
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
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
        HAL_OTBN_SHA256_Init();
#else
        HAL_LSSHA_SHA256_Init();
#endif
    }

    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (!ctx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    HAL_OTBN_SHA256_Update((uint8_t *)input, ilen);
    ret = 0;
#else
    ret = HAL_LSSHA_Update(input, ilen);
#endif
    return ret;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    assert(ls_sha_ctx == ctx);
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    ls_otbn_mbedtls_update_callback(mbedtls_ls_otbn_sha256_handler,NULL);
    HAL_OTBN_SHA256_Final(output);
    ret = 0;
#else
    ret = HAL_LSSHA_Final(output);
#endif
    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}


#endif /* CONFIG_MBEDTLS_HARDWARE_SHA224_SHA256_SM3_LINKEDSEMI */