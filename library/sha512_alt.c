#include <assert.h>
#include <string.h>
#include "mbedtls/sha512.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "stdio.h"
#if CONFIG_SHA512_CLOCK_RESET
#include "reg_sysc_sec_cpu.h"
#endif

#if defined(CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_OTBN_ALT)
#include "ls_hal_otbn_sha.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"
#include "platform.h"
void mbedtls_ls_otbn_moudle_init(void);
void mbedtls_ls_otbn_moudle_deinit(void);
void mbedtls_ls_otbn_threading_release(void);
bool mbedtls_ls_otbn_is_operation_current_thread(void);
int mbedtls_ls_otbn_operation_init(ls_otbn_fireware_t fireware_id);
void ls_otbn_mbedtls_update_callback(void (*func)(void*),void *param);
// static struct k_sem wait_complete;
// static void mbedtls_ls_otbn_sha512_handler()
// {
//     if (LSOTBN->INTR_STATE)
//     {
//         LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
//         // k_sem_give(&wait_complete);

//     }
// }
#endif

#if defined(CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_HARDWARE_ALT)
#include <ls_hal_sha512.h>
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha512_context* ls_sha_ctx = NULL;

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
    // mbedtls_zephyr_threading_init();
    mbedtls_mutex_init(&doneLock);
    
    #if CONFIG_SHA512_CLOCK_RESET
    #include "reg_sysc_sec_cpu.h"
        SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_CLR_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_CLR_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_SET_SHA512_MASK;
        SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_SET_SHA512_MASK;
    #endif
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
        ctx->is384 = true;
        HAL_SHA384_SHA384_Init();
    } else {
        ctx->is384 = false;
        HAL_SHA512_SHA512_Init();
    }

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

    HAL_SHA512_SHA512_Update((uint32_t *)input, ilen);
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    assert(ls_sha_ctx == ctx);
    HAL_SHA512_SHA512_Final(output);

    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return 0;
}


#endif /*CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_HARDWARE_ALT */

#if defined(CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_OTBN_ALT)

#define MBEDTLS_ERR_LS_OTBN_BUSY -0x135

#if defined(CONFIG_MEBDTLS_ECDSA_LINKEDSEMI_DELEGATION_SERVER)

static mbedtls_sha512_context* ls_sha_ctx = NULL;

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
    
    // k_sem_init(&wait_complete,0,1);
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
    int err = 0;
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

    err = mbedtls_ls_otbn_operation_init(((is384 == true)?OBTN_SHA384:OTBN_SHA512));
    if(err)
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

    if (is384) 
    {
        ctx->is384 = true;
        HAL_OTBN_SHA384_Init(); // otbn init

    } else {
        ctx->is384 = false;
        HAL_OTBN_SHA512_Init(); // otbn init

    }

    // k_sem_reset(&wait_complete);
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{

    if(!mbedtls_ls_otbn_is_operation_current_thread())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

    if (!ctx->start_calc_symbol)
    {
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);

#if defined(MBEDTLS_SHA384_C)
    if(ctx->is384)
    {
        HAL_OTBN_SHA384_Update((uint8_t *)input, ilen);
    }else
#endif //MBEDTLS_SHA384_C
    {
        HAL_OTBN_SHA512_Update((uint8_t *)input, ilen);
    }
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    assert(ls_sha_ctx == ctx);
    unsigned int key;

    if(!mbedtls_ls_otbn_is_operation_current_thread())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

#if defined(MBEDTLS_SHA384_C)
    if(ctx->is384)
    {
        HAL_OTBN_SHA384_Final(output);
    }else
#endif //MBEDTLS_SHA384_C
    {
        HAL_OTBN_SHA512_Final(output);
    }

    /* The hash algorithm on the OTBN is currently executed using the blocking method only. */
    // ls_otbn_mbedtls_update_callback(mbedtls_ls_otbn_sha512_handler,NULL);
    key = irq_lock();

    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_ls_otbn_moudle_deinit();
    mbedtls_ls_otbn_threading_release();

    irq_unlock(key);
    return 0;
}

#else

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    return 0;
}

#endif /*CONFIG_MEBDTLS_ECDSA_LINKEDSEMI_DELEGATION_SERVER*/

#endif /* CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_OTBN_ALT */
