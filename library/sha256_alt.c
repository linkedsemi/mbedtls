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

#if defined(CONFIG_MBEDTLS_SHA256_SM3_LINKEDSEMI_OTBN_ALT)
#include "ls_hal_otbn_sha.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"
#include "platform.h"
#include "mbedtls_otbn_hash.h"
#include "ls_otbn_config.h"
void mbedtls_ls_otbn_moudle_init(void);
int mbedtls_ls_otbn_operation_init(otbn_firmware_t firmware_id);

#endif

#if defined(CONFIG_MBEDTLS_SHA224_SHA256_SM3_LINKEDSEMI_HARDWARE_ALT)

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
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
    #if CONFIG_SOC_LS1010
        HAL_LSSHA_DeInit();
    #elif CONFIG_SOC_LSQSH
        #if CONFIG_SHA256_CLOCK_RESET
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SHA_MASK;
        #endif
    #endif
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

    ret = HAL_LSSHA_Update(input, ilen);

    return ret;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    assert(ls_sha_ctx == ctx);

    ret = HAL_LSSHA_Final(output);

    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}

#endif /*CONFIG_MBEDTLS_SHA224_SHA256_SM3_LINKEDSEMI_HARDWARE_ALT*/

#if defined(CONFIG_MBEDTLS_SHA256_SM3_LINKEDSEMI_OTBN_ALT)

#if !defined(CONFIG_MBEDTLS_LINKEDSEMI_OTBN_DELEGATION_CLIENT)
#define MBEDTLS_ERR_LS_OTBN_BUSY -0x135
static mbedtls_sha256_context* ls_sha_ctx = NULL;

void mbedtls_sm3_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
}

int mbedtls_sm3_starts(mbedtls_sha256_context *ctx)
{
    int err;

    err = mbedtls_ls_otbn_operation_init(OTBN_FIRMWARE_SM3);
    if(err)
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }
    ls_otbn_sm3_init_for_rtos();

    return 0;
}

int mbedtls_sm3_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    int ret = 0;

    if(!ls_otbn_session_is_owner())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }
    if (!ctx->start_calc_symbol)
    {
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);

    ls_otbn_sm3_update_for_rtos((uint8_t *)input, ilen);

    return ret;
}

void reversion_sm3_hash(uint8_t *input,uint8_t *output)
{
    uint32_t tmp[8];
    memcpy((uint8_t *)tmp,input,32);
    for(uint8_t i = 0; i < 8; i++)
    {
        *output++ = (uint8_t)(tmp[7 - i] >> 0);
        *output++ = (uint8_t)(tmp[7 - i] >> 8);
        *output++ = (uint8_t)(tmp[7 - i] >> 16);
        *output++ = (uint8_t)(tmp[7 - i] >> 24);
    }
}

int mbedtls_sm3_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    int ret = 0;
    assert(ls_sha_ctx == ctx);
    unsigned int key;
    if(!ls_otbn_session_is_owner())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

    ls_otbn_sm3_final_for_rtos(output);
    reversion_sm3_hash(output,output);
    key = irq_lock();

    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    ls_otbn_session_release();
    irq_unlock(key);

    return ret;
}

void mbedtls_sm3_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));


    // k_sem_init(&wait_complete,0,1);

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
    int err;
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
        /* not support */
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }else{
        err = mbedtls_ls_otbn_operation_init(OTBN_FIRMWARE_SHA256);
        if(err)
        {
            return MBEDTLS_ERR_LS_OTBN_BUSY;
        }
        ls_otbn_sha256_init_for_rtos();
    }

    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    int ret = 0;

    if(!ls_otbn_session_is_owner())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

    if (!ctx->start_calc_symbol)
    {
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);

    ls_otbn_sha256_update_for_rtos((uint8_t *)input, ilen);

    return ret;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    int ret = 0;
    assert(ls_sha_ctx == ctx);
    unsigned int key;
    if(!ls_otbn_session_is_owner())
    {
        return MBEDTLS_ERR_LS_OTBN_BUSY;
    }

    ls_otbn_sha256_final_for_rtos(output);

    key = irq_lock();

    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    ls_otbn_session_release();

    irq_unlock(key);
    return ret;
}

#else

void mbedtls_sm3_init(mbedtls_sha256_context *ctx)
{
}

int mbedtls_sm3_starts(mbedtls_sha256_context *ctx)
{
    return 0;
}

int mbedtls_sm3_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return 0;
}

void reversion_sm3_hash(uint8_t *input,uint8_t *output)
{
}

int mbedtls_sm3_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    return 0;
}

void mbedtls_sm3_free(mbedtls_sha256_context *ctx)
{
}

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

#endif /* CONFIG_MBEDTLS_SHA256_SM3_LINKEDSEMI_OTBN_ALT */


#if defined(CONFIG_MBEDTLS_SHA224_SHA256_SM3_LINKEDSEMI_HARDWARE_ALT) && defined(CONFIG_DMA)

#include <zephyr/drivers/dma.h>
#include <zephyr/drivers/dma/dma_dw.h>
#include <soc_dma.h>
#include "dmac_config.h"
#include "field_manipulate.h"
#include "reg_sha_type.h"
#include "platform.h"
#include <zephyr/cache.h>
struct k_sem dma_sem;
struct k_sem sha224_sha256_sm3_sem;

// #define CONFIG_SHA224_SHA256_SM3_DMA1
#define CONFIG_SHA224_SHA256_SM3_DMA_CHANNEL 7

#if defined(CONFIG_SHA224_SHA256_SM3_DMA1)
#define dmac DEVICE_DT_GET(DT_NODELABEL(dmac1))
#else
#define dmac DEVICE_DT_GET(DT_NODELABEL(dmac2))
#endif

#define SHA_BLOCK_SIZE 64
#define SHA224_SHA256_SM3_DMA_WAIT_TIMEOUT_MS 100000
#define SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE (2047*4/SHA_BLOCK_SIZE)
#define SHA224_SHA256_SM3_DMA_MAX_BYTES      (SHA224_SHA256_SM3_DMA_MAX_BLOCK_SIZE * SHA_BLOCK_SIZE)
#define SHA_PADDING_MOD 56

static uint32_t current_word;
static uint8_t current_block_bytes;
static uint64_t total_length;

static void sha_variable_init()
{
    total_length = 0;
    current_block_bytes = 0;
    current_word = 0;
}

int LSSHA_SHA256_Init()
{
    LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,0)|FIELD_BUILD(SHA_CALC_SM3,0);
    sha_variable_init();
    return HAL_OK;
}

int LSSHA_SHA224_Init()
{
    LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,1)|FIELD_BUILD(SHA_CALC_SM3,0);
    sha_variable_init();
    return HAL_OK;
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
        if(!end)    LSSHA->SHA_START = 1;
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

void mbedtls_sha256_init_dma(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
    mbedtls_mutex_init(&doneLock);
    k_sem_init(&dma_sem, 0, 1);
    k_sem_init(&sha224_sha256_sm3_sem, 0, 1);
    #if CONFIG_SOC_LSQSH
        #if CONFIG_SHA256_CLOCK_RESET
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_CALC_SHA_MASK;
            SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_CALC_SHA_MASK;
        #endif
        IRQ_CONNECT(CALC_SHA_IRQN, 3, LSSHA224_SHA256_SM3_IRQHandler,NULL, 0);
        irq_enable(CALC_SHA_IRQN);
    #endif
}

int mbedtls_sha256_starts_dma(mbedtls_sha256_context *ctx, int is224)
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

    LSSHA->INTR_M = 0;
    LSSHA->INTR_C = SHA_FSM_END_INTR_MASK | SHA_FSM_EMPT_INTR_MASK;

    if(is224)
    {
        LSSHA_SHA224_Init();
    }else{
        LSSHA_SHA256_Init();
    }

    return 0;
}

int mbedtls_sha256_update_dma(mbedtls_sha256_context *ctx,
                          const unsigned char *input, size_t ilen)
{
    if (!ctx->start_calc_symbol)
    {
        mbedtls_mutex_lock(&doneLock);
        ls_sha_ctx = ctx;
        ctx->start_calc_symbol = true;
    }
    assert(ls_sha_ctx == ctx);

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
    return 0;
}

int mbedtls_sha256_finish_dma(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    assert(ls_sha_ctx == ctx);
    ret = LSSHA_Final(output);
    ls_sha_ctx = NULL;
    ctx->start_calc_symbol = false;
    mbedtls_mutex_unlock(&doneLock);
    return ret;
}

int LSSHA_SM3_Init()
{
    LSSHA->SHA_CTRL = FIELD_BUILD(SHA_FST_DAT,1)|FIELD_BUILD(SHA_CALC_SHA224,0)|FIELD_BUILD(SHA_CALC_SM3,1);
    sha_variable_init();
    return HAL_OK;
}

void mbedtls_sm3_init_dma(mbedtls_sha256_context *ctx)
{
    mbedtls_sha256_init_dma(ctx);
}

int mbedtls_sm3_starts_dma(mbedtls_sha256_context *ctx)
{
    LSSHA->INTR_M = 0;
    LSSHA->INTR_C = SHA_FSM_END_INTR_MASK | SHA_FSM_EMPT_INTR_MASK;
    LSSHA_SM3_Init();
    return 0;
}

int mbedtls_sm3_update_dma(mbedtls_sha256_context *ctx,
                        const unsigned char *input,
                          size_t ilen)
{
    return mbedtls_sha256_update_dma(ctx, input, ilen);
}

int mbedtls_sm3_finish_dma(mbedtls_sha256_context *ctx,
                          unsigned char *output)
{
    return mbedtls_sha256_finish_dma(ctx, output);
}
#endif /*CONFIG_MBEDTLS_SHA224_SHA256_SM3_LINKEDSEMI_HARDWARE_ALT && CONFIG_DMA */
