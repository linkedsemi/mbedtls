#include <assert.h>
#include <string.h>
#include "mbedtls/sha512.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"

#if CONFIG_SHA512_CLOCK_RESET
#include "reg_sysc_sec_cpu.h"
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
void ls_otbn_mbedtls_update_callback(void (*func)(void*),void *param);
static struct k_sem wait_complete;
static void mbedtls_ls_otbn_sha512_handler()
{
    if (LSOTBN->INTR_STATE)
    {
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
        // k_sem_give(&wait_complete);

    }
}
#endif

#if defined(CONFIG_MBEDTLS_HARDWARE_SHA384_SHA512_LINKEDSEMI)
#include <ls_hal_sha512.h>
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha512_context* ls_sha_ctx = NULL;

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
    // mbedtls_zephyr_threading_init();
    mbedtls_mutex_init(&doneLock);
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    mbedtls_ls_otbn_moudle_init();
    k_sem_init(&wait_complete,0,1);
#else
    #if CONFIG_SHA512_CLOCK_RESET
    #include "reg_sysc_sec_cpu.h"
        SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_CLR_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_CLR_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_SET_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_SET_SHA512_MASK;
    #endif
#endif
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    mbedtls_ls_otbn_moudle_deinit();
#endif
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
        ctx->is384 = true;
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
        HAL_OTBN_SHA384_Init(); // otbn init
#else
        HAL_SHA384_SHA384_Init();
#endif
    } else {
        ctx->is384 = false;
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
        HAL_OTBN_SHA512_Init(); // otbn init
#else
        HAL_SHA512_SHA512_Init();
#endif
    }

#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
    k_sem_reset(&wait_complete);
#endif
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    if (!ctx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);

#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
#if defined(MBEDTLS_SHA384_C)
    if(ctx->is384)
    {
        HAL_OTBN_SHA384_Update((uint8_t *)input, ilen);
    }else
#endif //MBEDTLS_SHA384_C
    {
        HAL_OTBN_SHA512_Update((uint8_t *)input, ilen);
    }
#else
    HAL_SHA512_SHA512_Update((uint32_t *)input, ilen);
#endif
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    assert(ls_sha_ctx == ctx);
#if defined(CONFIG_ENABLE_LS_OTBN_HASH)
#if defined(MBEDTLS_SHA384_C)
    if(ctx->is384)
    {
        HAL_OTBN_SHA384_Final(output);
    }else
#endif //MBEDTLS_SHA384_C
    {
        HAL_OTBN_SHA512_Final(output);
    }
    ls_otbn_mbedtls_update_callback(mbedtls_ls_otbn_sha512_handler,NULL);
#else
    HAL_SHA512_SHA512_Final(output);
#endif
    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return 0;
}


#endif /* CONFIG_MBEDTLS_HARDWARE_SHA384_SHA512_LINKEDSEMI */