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
#include "otbn_hash.h"
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
__attribute__((aligned(4))) static uint8_t buffer[0x80];

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE 8
#endif
__attribute__((aligned(4))) static uint8_t temp_sram_buffer[MAX_BLOCK_SIZE*LS_SHA512_BLOCK_SIZE];

static inline bool is_sram_address(uint32_t addr) {
    return ((addr >= 0x10000000 && addr < 0x10140000)
            || (addr >= 0x30000000 && addr < 0x30140000));
}

struct k_sem sha384_sha512_sem;
#define SHA384_SHA512_WAIT_TIMEOUT_MS 100000
static uint64_t total_cnt;
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
    LS_SHA512->ADDR = addr & (~BIT(29));
    assert(((uint32_t)addr % 4) == 0);
    csi_dcache_clean_range((void *)addr, block_number*LS_SHA512_BLOCK_SIZE);
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
#if CONFIG_SHA512_CLOCK_RESET
    SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_CLR_SHA512_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_CLR_SHA512_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[0] = SYSC_SEC_CPU_SRST_SET_SHA512_MASK;
    SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_SET_SHA512_MASK;
#endif
    mbedtls_mutex_init(&doneLock);
    k_sem_init(&sha384_sha512_sem, 0, 1);
    buffer_idx = 0;
    total_cnt = 0;
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
    buffer_idx = 0;
    total_cnt = 0;
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha512_context));
#if CONFIG_SHA512_CLOCK_RESET
    SYSC_SEC_CPU->PD_CPU_CLKG[0] = SYSC_SEC_CPU_CLKG_CLR_SHA512_MASK;
#endif
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

int linkedsemi_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    if (!ctx->start_calc_symbol) {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }

    assert(ls_sha_ctx == ctx);
    assert(is_sram_address((uint32_t)input) && ((uint32_t)input % 4) == 0);

    total_cnt += ilen;

    if (ilen) {
        if (buffer_idx) {
            if ((ilen + buffer_idx) < LS_SHA512_BLOCK_SIZE) {
                memcpy(buffer + buffer_idx, input, ilen);
                buffer_idx += ilen;
                return 0;
            } else {
                uint32_t wr_len = LS_SHA512_BLOCK_SIZE - buffer_idx;
                memcpy((uint8_t *)buffer + buffer_idx, input, wr_len);
                block_calculate((uint32_t)buffer, 1);
                buffer_idx = 0;
                ilen -= wr_len;
                input += wr_len;
            }
        }
    }

    uint32_t block_number = ilen / LS_SHA512_BLOCK_SIZE;
    if (block_number) {
        if ((uint32_t)input % 4) {
            for (uint32_t i = 0; i < block_number / MAX_BLOCK_SIZE; i++) {
                memcpy(temp_sram_buffer, input, sizeof(temp_sram_buffer));
                block_calculate((uint32_t)temp_sram_buffer, MAX_BLOCK_SIZE);
                input += sizeof(temp_sram_buffer);
            }
            if (block_number % MAX_BLOCK_SIZE) {
                memcpy(temp_sram_buffer, input, (block_number % MAX_BLOCK_SIZE) * LS_SHA512_BLOCK_SIZE);
                block_calculate((uint32_t)temp_sram_buffer, block_number % MAX_BLOCK_SIZE);
                input += (block_number % MAX_BLOCK_SIZE) * LS_SHA512_BLOCK_SIZE;
            }
        }else{
            block_calculate((uint32_t)input, block_number);
            input += block_number * LS_SHA512_BLOCK_SIZE;
        }
    }

    if (ilen % LS_SHA512_BLOCK_SIZE) {
        memcpy((uint8_t *)buffer, input, ilen % LS_SHA512_BLOCK_SIZE);
        buffer_idx = ilen % LS_SHA512_BLOCK_SIZE;
    }
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    if (is_sram_address((uint32_t)input) && ((uint32_t)input % 4) == 0) {
        linkedsemi_sha512_update(ctx, input, ilen);
    } else {
        uint8_t *current = (uint8_t *)input;
        uint32_t remain = ilen % sizeof(temp_sram_buffer);

        for(uint32_t blk = 0; blk < (ilen / sizeof(temp_sram_buffer)); blk++) {
            memcpy(temp_sram_buffer, current, sizeof(temp_sram_buffer));
            linkedsemi_sha512_update(ctx, temp_sram_buffer, sizeof(temp_sram_buffer));
            current += sizeof(temp_sram_buffer);
        }
        if (remain) {
            memcpy(temp_sram_buffer, current, remain);
            linkedsemi_sha512_update(ctx, temp_sram_buffer, remain);
        }
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

static int otbn_err_to_mbedtls(int err)
{
    if (err == 0) {
        return 0;
    }
    return MBEDTLS_ERR_LS_OTBN_BUSY;
}

#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
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

    ctx->is384 = is384 ? true : false;

    return otbn_err_to_mbedtls(otbn_hash_init(
        &ctx->otbn,
        is384 ? OTBN_HASH_ALGO_SHA384 : OTBN_HASH_ALGO_SHA512));
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return otbn_err_to_mbedtls(otbn_hash_update(&ctx->otbn, input, (uint32_t)ilen));
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output)
{
    return otbn_err_to_mbedtls(otbn_hash_final(&ctx->otbn, output));
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

#endif /* CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT */

#endif /* CONFIG_MBEDTLS_SHA384_SHA512_LINKEDSEMI_OTBN_ALT */
