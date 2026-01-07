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
#include "mbedtls_otbn_hash.h"
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
#include "field_manipulate.h"
#include <zephyr/cache.h>
#include "reg_sha512_type.h"
#include <core_rv32.h>
#include "qsh.h"
static mbedtls_threading_mutex_t doneLock;
static mbedtls_sha512_context* ls_sha_ctx = NULL;
__attribute__((aligned(4))) static uint32_t buffer[0x20];
struct k_sem sha384_sha512_sem;
#define SHA384_SHA512_WAIT_TIMEOUT_MS 100000
static uint32_t total_cnt;
static uint32_t buffer_idx;
static bool isFirst;
static uint8_t read_reg_count;

void LSSHA384_SHA512_IRQHandler(void)
{
    if(LS_SHA512->INTR_STT & SHA512_INTR_CALC_END_MASK)
    {
        LS_SHA512->INTR_CLR = LS_SHA512->INTR_STT;
        LS_SHA512->INTR_MSK = 0x0;
        k_sem_give(&sha384_sha512_sem);
    }
}

static void block_calculate(uint32_t addr, uint32_t block_number)
{
    while ((LS_SHA512->STATUS & 0x1) != 0x1) ;
    REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_BLOCK_NUM, (block_number - 1));
    LS_SHA512->ADDR = addr;
    assert(((uint32_t)addr % 4) == 0);
    csi_dcache_clean_range((uint32_t *)addr, block_number*LS_SHA512_BLOCK_SIZE);
    // Hardware requirements include 610 and 810 development boards : 
    // 1.irq_disable, 2.start, 3.intr_clr, 4.irq_enable, 5.intr_mask
    irq_disable(SHA512_IRQN);

    if (isFirst)
    {
        REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_INIT_CALC, 1);
        REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_START, 1);
        isFirst = false;
    }
    else
    {
        REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_INIT_CALC ,0);
        REG_FIELD_WR(LS_SHA512->CTRL, SHA512_CTRL_START, 1);
    }

    LS_SHA512->INTR_CLR = SHA512_INTR_DMA_END_MASK | SHA512_INTR_CALC_END_MASK;

    irq_enable(SHA512_IRQN);

    LS_SHA512->INTR_MSK = SHA512_INTR_CALC_END_MASK;

    k_sem_take(&sha384_sha512_sem, K_MSEC(SHA384_SHA512_WAIT_TIMEOUT_MS));
}

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
    mbedtls_mutex_init(&doneLock);
    k_sem_init(&sha384_sha512_sem, 0, 1);
    LS_SHA512->INTR_MSK = 0x0;
    LS_SHA512->INTR_CLR = SHA512_INTR_DMA_END_MASK | SHA512_INTR_CALC_END_MASK;
    IRQ_CONNECT(SHA512_IRQN, 3, LSSHA384_SHA512_IRQHandler,NULL, 0);
    irq_enable(SHA512_IRQN);
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
        isFirst = true;
        read_reg_count = 12;
        LS_SHA512->CTRL = 0x8;
    } else {
        ctx->is384 = false;
        isFirst = true;
        read_reg_count = 16;
        LS_SHA512->CTRL = 0xc;
    }

    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    if (ilen == 0) {
        return 0;
    }

    if (!ctx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);
    assert(((uint32_t)input % 4) == 0);
    uint8_t *msg = (uint8_t *)input;
    total_cnt += ilen;

    if (buffer_idx)
    {
        if ((ilen + buffer_idx) < LS_SHA512_BLOCK_SIZE)
        {
            memcpy(&buffer[buffer_idx], input, ilen);
            buffer_idx += ilen;
            return 0;
        }
        uint32_t wr_len = LS_SHA512_BLOCK_SIZE - buffer_idx;
        memcpy(&buffer[buffer_idx], msg, wr_len);
        block_calculate((uint32_t)buffer, 1);
        buffer_idx = 0;
        ilen -= wr_len;
        msg += wr_len;
    }

    uint32_t block_number = ilen / LS_SHA512_BLOCK_SIZE;
    if (block_number)
        block_calculate((uint32_t)msg, block_number);

    if (ilen % LS_SHA512_BLOCK_SIZE)
    {
        memcpy(&buffer[buffer_idx], msg + (block_number * LS_SHA512_BLOCK_SIZE), ilen % LS_SHA512_BLOCK_SIZE);
        buffer_idx = ilen % LS_SHA512_BLOCK_SIZE;
    }
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    assert(ls_sha_ctx == ctx);
    uint8_t *p_buffer = (uint8_t *)buffer;
    uint64_t bit_cnt = total_cnt * 8;
    p_buffer[buffer_idx++] = 0x80;
    if (buffer_idx == LS_SHA512_BLOCK_SIZE)
    {
        block_calculate((uint32_t)buffer, 1);
        buffer_idx = 0;
    }

    while (buffer_idx != (LS_SHA512_BLOCK_SIZE - 0x10))
    {
        p_buffer[buffer_idx++] = 0x0;
        if (buffer_idx == LS_SHA512_BLOCK_SIZE)
        {
            block_calculate((uint32_t)buffer, 1);
            buffer_idx = 0;
        }
    }
    memset(&p_buffer[buffer_idx], 0x0, 8);
    buffer_idx += 8;

    for (uint8_t i = 0; i < 8; i++)
    {
        p_buffer[buffer_idx + (7 - i)] = (uint8_t)(bit_cnt >> (8 * i));
    }
    buffer_idx += 8;
    block_calculate((uint32_t)buffer, 1);
    for (uint8_t j = 0; j < read_reg_count; j++)
    {
        uint32_t in = LS_SHA512->DIGEST[15 - j];
        *output++ = in >> 24;
        *output++ = in >> 16;
        *output++ = in >> 8;
        *output++ = in;
    }
    buffer_idx = 0;
    total_cnt = 0;
    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return 0;
}


#endif /*CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_HARDWARE_ALT */

#if defined(CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_OTBN_ALT)

#define MBEDTLS_ERR_LS_OTBN_BUSY -0x135

#if !defined(CONFIG_MEBDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)

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
        ls_otbn_sha384_init_for_rtos(); // otbn init

    } else {
        ctx->is384 = false;
        ls_otbn_sha512_init_for_rtos(); // otbn init

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
        ls_otbn_sha384_update_for_rtos((uint8_t *)input, ilen);
    }else
#endif //MBEDTLS_SHA384_C
    {
        ls_otbn_sha512_update_for_rtos((uint8_t *)input, ilen);
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
        ls_otbn_sha384_final_for_rtos(output);
    }else
#endif //MBEDTLS_SHA384_C
    {
        ls_otbn_sha512_final_for_rtos(output);
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
