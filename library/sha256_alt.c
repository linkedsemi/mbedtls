#include <assert.h>
#include <stdio.h>
#include <ls_hal_sha.h>
#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "../include/mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "field_manipulate.h"
#include <zephyr/kernel.h>

#if CONFIG_SOC_LSQSH
    #include "qsh.h"
    #if CONFIG_SHA256_CLOCK_RESET
        #include "reg_sysc_sec_cpu.h"
    #endif
#endif

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_OTBN_ALT)||defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT)
#include "otbn_hash.h"
#endif

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT)||defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)
#include "mbedtls/sm3_alt.h"
#endif

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT) || defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)

static mbedtls_threading_mutex_t doneLock;
static bool done_lock_initialized = false;

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)
#define LS_SHA_ALT_CTX_TYPE mbedtls_sm3_context
#else
#define LS_SHA_ALT_CTX_TYPE mbedtls_sha256_context
#endif

#define SHA_BLOCK_SIZE 64
#define SHA_PADDING_MOD 56

#if defined(CONFIG_DMA)
#include <zephyr/cache.h>

struct k_sem dma_sem;
struct k_sem sha224_sha256_sm3_sem;

#define SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS 10000
#define SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE (2047*4/SHA_BLOCK_SIZE)
#define SHA224_SHA256_SM3_DMA_MAX_BYTES      (SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE * SHA_BLOCK_SIZE)

void LSSHA224_SHA256_SM3_IRQHandler(void);
static void dma_conf(uint32_t source_address, uint32_t dest_address, size_t ilen);
static void sha_dma_stop(void);
#endif

static uint32_t current_word;
static uint8_t current_block_bytes;
static uint64_t total_length;
static bool block_needs_start;

static void ls_sha_hw_save_state(LS_SHA_ALT_CTX_TYPE *c)
{
    c->hw_current_word = current_word;
    c->hw_current_block_bytes = current_block_bytes;
    c->hw_total_length = total_length;
    c->hw_block_needs_start = block_needs_start;
}

static void ls_sha_hw_restore_state(LS_SHA_ALT_CTX_TYPE *c)
{
    current_word = c->hw_current_word;
    current_block_bytes = c->hw_current_block_bytes;
    total_length = c->hw_total_length;
    block_needs_start = c->hw_block_needs_start;
}

static void byte_update(const uint8_t val)
{
    switch(current_block_bytes%sizeof(uint32_t))
    {
    case 0:
        MODIFY_REG(current_word,0xff,val);
    break;
    case 1:
        MODIFY_REG(current_word,0xff00,val<<8);
    break;
    case 2:
        MODIFY_REG(current_word,0xff0000,val<<16);
    break;
    case 3:
        MODIFY_REG(current_word,0xff000000,val<<24);
    break;
    }
    current_block_bytes++;
    if(current_block_bytes%sizeof(uint32_t)==0)
    {
        LSSHA->FIFO_DAT = current_word;
    }
}

static void sha_start(bool end)
{
    if(current_block_bytes==SHA_BLOCK_SIZE)
    {
        current_block_bytes = 0;
        while((LSSHA->INTR_R&SHA_FSM_END_INTR_MASK)==0);
        LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
        if(!end) {
            LSSHA->SHA_START = 1;
            block_needs_start = false;
        }
    }
}

int LSSHA_Final(uint8_t *digest)
{
    if(!current_block_bytes)
    {
        LSSHA->DMA_CTRL = 0;
        REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
        LSSHA->SHA_START = 1;
    }
    byte_update(0x80);
    while(current_block_bytes!=SHA_PADDING_MOD)
    {
        sha_start(false);
        byte_update(0x00);
    }
    byte_update(total_length>>56);
    byte_update(total_length>>48);
    byte_update(total_length>>40);
    byte_update(total_length>>32);
    byte_update(total_length>>24);
    byte_update(total_length>>16);
    byte_update(total_length>>8);
    byte_update(total_length>>0);
    sha_start(true);
    uint8_t i;
    uint8_t count = REG_FIELD_RD(LSSHA->SHA_CTRL,SHA_CALC_SHA224) != 1 ? SHA256_WORDS_NUM : SHA224_WORDS_NUM;
    for (i = 0; i < count; ++i)
    {
        uint32_t val = LSSHA->SHA_RSLT[i];
        *digest++ = val>>24;
        *digest++ = val>>16;
        *digest++ = val>>8;
        *digest++ = val;
    }
    return 0;
}

static void ls_sha_hw_init(void)
{
    // mbedtls_zephyr_threading_init();
    if (!done_lock_initialized) {
        mbedtls_mutex_init(&doneLock);
        done_lock_initialized = true;
    }
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
#if defined(CONFIG_DMA)
    k_sem_init(&dma_sem, 0, 1);
    k_sem_init(&sha224_sha256_sm3_sem, 0, 1);
    #if CONFIG_SOC_LSQSH
        IRQ_CONNECT(CALC_SHA_IRQN, 3, LSSHA224_SHA256_SM3_IRQHandler, NULL, 0);
        irq_enable(CALC_SHA_IRQN);
    #endif
#endif
}

static void ls_sha_hw_deinit(void)
{
    #if CONFIG_SOC_LS1010
        HAL_LSSHA_DeInit();
    #elif CONFIG_SOC_LSQSH
        #if CONFIG_SHA256_CLOCK_RESET
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SHA_MASK;
        #endif
    #endif
}

static int ls_sha_hw_update_core(LS_SHA_ALT_CTX_TYPE *c,
                                 const unsigned char *input,
                                 size_t ilen);
static int ls_sha_hw_update_dma_core(LS_SHA_ALT_CTX_TYPE *c,
                                     const unsigned char *input,
                                     size_t ilen);
static int ls_sha_hw_update(void *ctx,
                            const unsigned char *input,
                            size_t ilen);
static int ls_sha_hw_update_dma(void *ctx,
                                const unsigned char *input,
                                size_t ilen);
static int ls_sha_hw_final(void *ctx,
                           unsigned char *output);

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)

void mbedtls_sm3_init(mbedtls_sm3_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ls_sha_hw_init();
}

int mbedtls_sm3_starts(mbedtls_sm3_context *ctx)
{
    /* starts 重置引擎级静态状态并切换算法（HAL_LSSHA_SM3_Init），必须在锁内
     * 执行，防止打断其他在途流式调用；随后把初始状态存入本 ctx 快照，
     * 之后该 ctx 的 update/final 从快照恢复。 */
    mbedtls_mutex_lock(&doneLock);
    LSSHA->INTR_M = 0;
    LSSHA->INTR_C = SHA_FSM_END_INTR_MASK | SHA_FSM_EMPT_INTR_MASK;
    current_word = 0;
    current_block_bytes = 0;
    total_length = 0;
    block_needs_start = true;
    HAL_LSSHA_SM3_Init();
    ls_sha_hw_save_state((LS_SHA_ALT_CTX_TYPE *)ctx);
    mbedtls_mutex_unlock(&doneLock);
    return 0;
}

int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    return ls_sha_hw_update((mbedtls_sha256_context *)ctx, input, ilen);
}

int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char *output)
{
    return ls_sha_hw_final((mbedtls_sha256_context *)ctx, output);
}

void mbedtls_sm3_free(mbedtls_sm3_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    ls_sha_hw_deinit();
}

#endif /* CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT */

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT)

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
    ls_sha_hw_init();
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
    ls_sha_hw_deinit();
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

    mbedtls_mutex_lock(&doneLock);
    LSSHA->INTR_M = 0;
    LSSHA->INTR_C = SHA_FSM_END_INTR_MASK | SHA_FSM_EMPT_INTR_MASK;
    current_word = 0;
    current_block_bytes = 0;
    total_length = 0;
    block_needs_start = true;

    if(is224)
    {
        HAL_LSSHA_SHA224_Init();
    }else{
        HAL_LSSHA_SHA256_Init();
    }
    ls_sha_hw_save_state((LS_SHA_ALT_CTX_TYPE *)ctx);
    mbedtls_mutex_unlock(&doneLock);

    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return ls_sha_hw_update(ctx, input, ilen);
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    return ls_sha_hw_final(ctx, output);
}

#endif /* CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT */

static int ls_sha_hw_update_core(LS_SHA_ALT_CTX_TYPE *c,
                                 const unsigned char *input,
                                 size_t ilen)
{

    /* Fill any partial block left from the previous update with CPU copy.
     * Only these bytes are accounted for here; the DMA path accounts for
     * the remainder itself.
     */
    if (current_block_bytes != 0 && ilen > 0) {
        size_t fill = ilen;
        if (fill > (size_t)(SHA_BLOCK_SIZE - current_block_bytes)) {
            fill = SHA_BLOCK_SIZE - current_block_bytes;
        }
        total_length += fill * 8;
        while (fill--) {
            byte_update(*input++);
            ilen--;
        }
        if (current_block_bytes == SHA_BLOCK_SIZE) {
            /* If the remainder is going through DMA, service the end of the
             * just-completed block but do not kick the next one; _dma will
             * issue SHA_START itself.
             */
            if (ilen >= SHA_BLOCK_SIZE && ((uintptr_t)input & 31U) == 0) {
                while ((LSSHA->INTR_R & SHA_FSM_END_INTR_MASK) == 0);
                LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
                current_block_bytes = 0;
                block_needs_start = true;
            } else if (ilen > 0) {
                sha_start(false);
            } else {
                /* This update ended exactly on a block boundary.  Don't
                 * start an empty block; leave the state machine ready for
                 * the next update / finish.
                 */
                while ((LSSHA->INTR_R & SHA_FSM_END_INTR_MASK) == 0);
                LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
                current_block_bytes = 0;
                block_needs_start = true;
            }
        }
    }

#if defined(CONFIG_DMA)
    /* The restored _dma interface expects a source address that is both
     * 4-byte aligned and cache-line aligned (the cache flush warns otherwise
     * and may leave the DMA transfer hanging on this SoC).
     */
    if (ilen >= SHA_BLOCK_SIZE && ((uintptr_t)input & 31U) == 0) {
        int dma_ret = ls_sha_hw_update_dma_core(c, input, ilen);
        if (dma_ret == 0 && current_block_bytes == 0) {
            block_needs_start = true;
        }
        LSSHA->DMA_CTRL = 0;
        sha_dma_stop();
        return dma_ret;
    }
#endif /* CONFIG_DMA */

    /* CPU copy for the remaining unaligned or short tail. */
    total_length += ilen * 8;
    REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
    while (ilen > 0) {
        if (block_needs_start) {
            LSSHA->SHA_START = 1;
            LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
            block_needs_start = false;
        }
        do {
            byte_update(*input++);
            ilen--;
        } while (current_block_bytes != SHA_BLOCK_SIZE && ilen > 0);

        if (current_block_bytes == SHA_BLOCK_SIZE) {
            if (ilen > 0) {
                sha_start(false);
            } else {
                /* End of this update on a block boundary: don't leave an
                 * empty block started; wait for the completed block and let
                 * the next update / finish issue SHA_START.
                 */
                while ((LSSHA->INTR_R & SHA_FSM_END_INTR_MASK) == 0);
                LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
                current_block_bytes = 0;
                block_needs_start = true;
            }
        }
    }

    return 0;
}

static int ls_sha_hw_update(void *ctx,
                            const unsigned char *input,
                            size_t ilen)
{
    LS_SHA_ALT_CTX_TYPE *c = (LS_SHA_ALT_CTX_TYPE *)ctx;
    int ret;

    mbedtls_mutex_lock(&doneLock);
    ls_sha_hw_restore_state(c);
    ret = ls_sha_hw_update_core(c, input, ilen);
    ls_sha_hw_save_state(c);
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}

static int ls_sha_hw_final(void *ctx,
                           unsigned char *output)
{
    LS_SHA_ALT_CTX_TYPE *c = (LS_SHA_ALT_CTX_TYPE *)ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;


    mbedtls_mutex_lock(&doneLock);
    ls_sha_hw_restore_state(c);
    ret = LSSHA_Final(output);
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}

#if defined(CONFIG_DMA)
static int ls_sha_hw_update_dma_core(LS_SHA_ALT_CTX_TYPE *c,
                                     const unsigned char *input, size_t ilen)
{
    /* The DMA flush on this SoC requires a cache-line aligned source address.
     * If a caller passes an unaligned buffer, fall back to CPU copy instead of
     * triggering the cache-line warning (and potential DMA hang).
     */
    if ((((uintptr_t)input) & (CONFIG_DCACHE_LINE_SIZE - 1)) != 0) {
        LSSHA->DMA_CTRL = 0;
        REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
        while (ilen > 0) {
            if (block_needs_start) {
                LSSHA->SHA_START = 1;
                LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
                block_needs_start = false;
            }
            do {
                byte_update(*input++);
                ilen--;
            } while (current_block_bytes != SHA_BLOCK_SIZE && ilen > 0);
            sha_start(false);
        }
        return 0;
    }

    uint32_t trans_count = ilen / SHA224_SHA256_SM3_DMA_MAX_BYTES;
    uint32_t dma_calc_bytes;
    uint32_t remain_len = 0;

    const unsigned char *dma_start_input = NULL;
    const unsigned char *remain_input = NULL;

    total_length += ilen*8;

    for(uint32_t i=0; i <= trans_count; i++)
    {
        if(trans_count == 0){
            REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, ilen/SHA_BLOCK_SIZE - 1);
            dma_calc_bytes = (ilen/SHA_BLOCK_SIZE)*SHA_BLOCK_SIZE;
            remain_len = ilen - dma_calc_bytes;
            dma_start_input = input;
            remain_input = input + dma_calc_bytes;
        }
        else if((i == trans_count) && (trans_count > 0)){
            dma_calc_bytes = ((ilen - SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count)/SHA_BLOCK_SIZE)*SHA_BLOCK_SIZE;
            if(dma_calc_bytes < SHA_BLOCK_SIZE)
            {
                remain_len = ilen - SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
                remain_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
            }else{
                REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, dma_calc_bytes/SHA_BLOCK_SIZE - 1);
                remain_len = ilen - (SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count) - dma_calc_bytes;
                dma_start_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * trans_count;
                remain_input = dma_start_input + dma_calc_bytes;
            }
        }
        else{
            REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE-1);
            dma_calc_bytes = SHA224_SHA256_SM3_DMA_MAX_BYTES;
            dma_start_input = input + SHA224_SHA256_SM3_DMA_MAX_BYTES * i;
        }

        if(dma_calc_bytes >= SHA_BLOCK_SIZE)
        {
            LSSHA->INTR_C = 3;
            LSSHA->INTR_M = SHA_FSM_END_INTR_MASK;
            LSSHA->SHA_START = 1;
            LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
            sys_cache_data_flush_range((void *)dma_start_input, dma_calc_bytes);
            LSSHA->DMA_CTRL = 1;
            dma_conf((uint32_t)dma_start_input, SEC_CALC_SHA_ADDR + 0x30, dma_calc_bytes);
            k_sem_take(&dma_sem,  K_MSEC(SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS));
            k_sem_take(&sha224_sha256_sm3_sem,  K_MSEC(SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS));
        }
    }

    if(remain_len)
    {
        LSSHA->DMA_CTRL = 0;
        REG_FIELD_WR(LSSHA->SHA_CTRL, SHA_SHA_LEN, 0);
        LSSHA->SHA_START = 1;
        LSSHA->SHA_CTRL &= ~SHA_FST_DAT_MASK;
        do{
            byte_update(*remain_input);
            remain_input++;
            remain_len--;
        }while(current_block_bytes!=SHA_BLOCK_SIZE&&remain_len);
    }

    /* If the CPU tail just completed a whole block, service its end and leave
     * the state machine ready for the next update / finish.
     */
    if (current_block_bytes == SHA_BLOCK_SIZE) {
        while ((LSSHA->INTR_R & SHA_FSM_END_INTR_MASK) == 0);
        LSSHA->INTR_C = SHA_FSM_END_INTR_MASK;
        current_block_bytes = 0;
        block_needs_start = true;
    }

    return 0;
}

static int ls_sha_hw_update_dma(void *ctx,
                                const unsigned char *input, size_t ilen)
{
    LS_SHA_ALT_CTX_TYPE *c = (LS_SHA_ALT_CTX_TYPE *)ctx;
    int ret;

    mbedtls_mutex_lock(&doneLock);
    ls_sha_hw_restore_state(c);
    ret = ls_sha_hw_update_dma_core(c, input, ilen);
    ls_sha_hw_save_state(c);
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}
#endif /* CONFIG_DMA */

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT)

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
    *dst = *src;
}

#if defined(CONFIG_DMA)
void mbedtls_sha256_init_dma(mbedtls_sha256_context *ctx)
{
    mbedtls_sha256_init(ctx);
}

int mbedtls_sha256_starts_dma(mbedtls_sha256_context *ctx, int is224)
{
    return mbedtls_sha256_starts(ctx, is224);
}

int mbedtls_sha256_finish_dma(mbedtls_sha256_context *ctx,
                              unsigned char *output)
{
    return ls_sha_hw_final(ctx, output);
}
#endif /* CONFIG_DMA */

#endif /* CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT */

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT) && defined(CONFIG_DMA)

void mbedtls_sm3_init_dma(mbedtls_sm3_context *ctx)
{
    mbedtls_sm3_init(ctx);
}

int mbedtls_sm3_starts_dma(mbedtls_sm3_context *ctx)
{
    return mbedtls_sm3_starts(ctx);
}

int mbedtls_sm3_update_dma(mbedtls_sm3_context *ctx,
                           const unsigned char *input,
                           size_t ilen)
{
    return ls_sha_hw_update_dma((mbedtls_sha256_context *)ctx, input, ilen);
}

int mbedtls_sm3_finish_dma(mbedtls_sm3_context *ctx,
                           unsigned char *output)
{
    return mbedtls_sm3_finish(ctx, output);
}

#endif /* CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT && CONFIG_DMA */

#endif /* CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT || CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT */

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_OTBN_ALT)||defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT)
#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
#include "otbn_hash.h"

#define MBEDTLS_ERR_LS_OTBN_BUSY -0x135

static int otbn_err_to_mbedtls(int err)
{
    if (err == 0) {
        return 0;
    }
    return MBEDTLS_ERR_LS_OTBN_BUSY;
}
#endif

#if defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT)
#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
void mbedtls_sm3_init(mbedtls_sm3_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sm3_context));
}

int mbedtls_sm3_starts(mbedtls_sm3_context *ctx)
{
    return otbn_err_to_mbedtls(otbn_hash_init(&ctx->otbn, OTBN_HASH_ALGO_SM3));
}

int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    return otbn_err_to_mbedtls(otbn_hash_update(&ctx->otbn, input, (uint32_t)ilen));
}

int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char *output)
{
    return otbn_err_to_mbedtls(otbn_hash_final(&ctx->otbn, output));
}

void mbedtls_sm3_free(mbedtls_sm3_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sm3_context));
}
#else

void mbedtls_sm3_init(mbedtls_sm3_context *ctx)
{
}

int mbedtls_sm3_starts(mbedtls_sm3_context *ctx)
{
    return 0;
}

int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    return 0;
}

int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char *output)
{
    return 0;
}

void mbedtls_sm3_free(mbedtls_sm3_context *ctx)
{
}
#endif
#endif /* CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT */

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_OTBN_ALT)
#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
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

    if (is224) {
        ctx->is224 = true;
        return otbn_err_to_mbedtls(otbn_hash_init(&ctx->otbn, OTBN_HASH_ALGO_SHA224));
    }

    ctx->is224 = false;
    return otbn_err_to_mbedtls(otbn_hash_init(&ctx->otbn, OTBN_HASH_ALGO_SHA256));
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return otbn_err_to_mbedtls(otbn_hash_update(&ctx->otbn, input, (uint32_t)ilen));
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    uint8_t tmp[32];
    int ret;

    ret = otbn_hash_final(&ctx->otbn, tmp);
    if (ret != 0) {
        return otbn_err_to_mbedtls(ret);
    }

    if (ctx->is224) {
        memcpy(output, tmp, 28);
    } else {
        memcpy(output, tmp, 32);
    }

    return 0;
}

#else

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    return 0;
}
#endif
#endif /* CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_OTBN_ALT */

#endif /* CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_OTBN_ALT || CONFIG_MBEDTLS_SM3_LINKEDSEMI_OTBN_ALT */


#if (defined(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT) || defined(CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT)) && defined(CONFIG_DMA)

#include <zephyr/drivers/dma.h>
#include <zephyr/drivers/dma/dma_dw.h>
#include <soc_dma.h>
#include "dmac_config.h"
#include "reg_sha_type.h"
#include "platform.h"
#include "reg_base_addr.h"
#include "reg_sysc_app_cpu.h"
#include "ls_msp_dmacv3.h"

extern struct k_sem dma_sem;
extern struct k_sem sha224_sha256_sm3_sem;

// #define CONFIG_SHA224_SHA256_SM3_DMA1
#define CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL 7

#if defined(CONFIG_SHA224_SHA256_SM3_DMA1)
#define dmac DEVICE_DT_GET(DT_NODELABEL(dmac1))
#else
#define dmac DEVICE_DT_GET(DT_NODELABEL(dmac2))
#endif

static void sha_dma_stop(void)
{
    dma_stop(dmac, CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL);
}

void LSSHA224_SHA256_SM3_IRQHandler(void)
{
    if(LSSHA->INTR_S & SHA_FSM_END_INTR_MASK)
    {
        LSSHA->INTR_C = LSSHA->INTR_S;
        LSSHA->INTR_M = 0;
        k_sem_give(&sha224_sha256_sm3_sem);
    }
}

static void sha224_sha256_sm3_dma_callback(const struct device *dev, void *user_data,
                   uint32_t channel, int status)
{
    if (status == DMA_STATUS_COMPLETE || status < 0) {
        k_sem_give(&dma_sem);
    }
}

static void dma_conf(uint32_t source_address, uint32_t dest_address, size_t ilen)
{
    uint32_t blk_cnt = ilen >> 2;
    uint8_t ret;
    struct dma_config dma_cfg;
    struct dma_block_config blk;
    blk.block_size = blk_cnt;
    blk.source_address  = source_address;
    blk.dest_address    = dest_address;
    blk.source_addr_adj = DMA_ADDR_ADJ_INCREMENT;
    blk.dest_addr_adj   = DMA_ADDR_ADJ_NO_CHANGE;
    blk.next_block      = NULL;
    /* Config DMA Config */
    memset(&dma_cfg, 0, sizeof(dma_cfg));
    dma_cfg.dma_slot            = DMA_SHA256;
    dma_cfg.channel_direction   = MEMORY_TO_PERIPHERAL;
    dma_cfg.complete_callback_en= 0;
    dma_cfg.channel_priority    = 0;
    dma_cfg.source_data_size    = 4;
    dma_cfg.dest_data_size      = 4;
    dma_cfg.source_burst_length = 8;
    dma_cfg.dest_burst_length   = 8;
    dma_cfg.block_count         = 1;
    dma_cfg.head_block          = &blk;
    dma_cfg.user_data           = NULL;
    dma_cfg.dma_callback        = sha224_sha256_sm3_dma_callback;

    ret = dma_config(dmac, CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL, &dma_cfg);
    if (ret < 0) {
        printk("dma_config failed %d", ret);
    }
    ret = dma_start(dmac, CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL);
    if (ret < 0) {
        printk("dma_start failed %d", ret);
    }
}

#endif /*(CONFIG_MBEDTLS_SHA224_SHA256_LINKEDSEMI_HARDWARE_ALT || CONFIG_MBEDTLS_SM3_LINKEDSEMI_HARDWARE_ALT) && CONFIG_DMA */
