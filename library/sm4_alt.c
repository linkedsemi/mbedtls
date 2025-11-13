#include "mbedtls/platform_util.h"
#include <string.h>
#include "mbedtls/sm4_alt.h"

#if CONFIG_SOC_LSQSH
    #include "ls_msp_sm4.h"
    #include "field_manipulate.h"
    #include "reg_sm4_type.h"
    #include <zephyr/cache.h>
#endif

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT)

#include <ls_hal_sm4.h>

#define SM4_IV_SIZE 16

void mbedtls_sm4_init(mbedtls_sm4_context *ctx)
{
#if CONFIG_SOC_LS1010
    HAL_SM4_Init();
#endif
}

void mbedtls_sm4_free(mbedtls_sm4_context *ctx)
{
#if CONFIG_SOC_LS1010
    HAL_SM4_DeInit();
#elif CONFIG_SOC_LSQSH
    #if CONFIG_SM4_CLOCK_RESET
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SM4_MASK;
    #endif
#endif
}

int mbedtls_sm4_setkey(const unsigned char* key)
{
    return HAL_SM4_KeyExpansion(key);
}

int mbedtls_sm4_setiv(mbedtls_sm4_context *ctx, const unsigned char* iv)
{
    memcpy(ctx->iv, iv, SM4_IV_SIZE);
    return 0;
}

int mbedtls_sm4_ecb_encrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    __ASSERT_NO_MSG(ilen % 16 == 0);

    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, (uint8_t)(ilen / 16 - 1));
    REG_FIELD_WR(LSSM4->SM4_CTRL,SM4_CALC_DEC,0);

    LSSM4->SM4_START = SM4_CALC_START_MASK;

    if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
    {
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
    }
    do
    {
        if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
        {
            *out++ = (LSSM4->CALC_RSLT0);
            *out++ = (LSSM4->CALC_RSLT1);
            *out++ = (LSSM4->CALC_RSLT2);
            *out++ = (LSSM4->CALC_RSLT3);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
        }

    } while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
    LSSM4->INTR_CLR = SM4_INTR_END_MASK;
    *out++ = (LSSM4->CALC_RSLT0);
    *out++ = (LSSM4->CALC_RSLT1);
    *out++ = (LSSM4->CALC_RSLT2);
    *out++ = (LSSM4->CALC_RSLT3);

    return 0;
}

int mbedtls_sm4_ecb_decrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    __ASSERT_NO_MSG(ilen % 16 == 0);

    uint32_t *in = (uint32_t *)input;
    uint32_t *out = (uint32_t *)output;

    REG_FIELD_WR(LSSM4->SM4_CTRL, SM4_CALC_LEN, (uint8_t)(ilen / 16 - 1));
    REG_FIELD_WR(LSSM4->SM4_CTRL,SM4_CALC_DEC,1);

    LSSM4->SM4_START = SM4_CALC_START_MASK;

    if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
    {
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->CALC_WRD = (*in++);
        LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
    }
    do
    {
        if(REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_DATA) == 1)
        {
            *out++ = (LSSM4->CALC_RSLT0);
            *out++ = (LSSM4->CALC_RSLT1);
            *out++ = (LSSM4->CALC_RSLT2);
            *out++ = (LSSM4->CALC_RSLT3);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->CALC_WRD = (*in++);
            LSSM4->INTR_CLR = SM4_INTR_DATA_MASK;
        }

    } while (REG_FIELD_RD(LSSM4->INTR_RAW, SM4_INTR_END) == 0);
    LSSM4->INTR_CLR = SM4_INTR_END_MASK;
    *out++ = (LSSM4->CALC_RSLT0);
    *out++ = (LSSM4->CALC_RSLT1);
    *out++ = (LSSM4->CALC_RSLT2);
    *out++ = (LSSM4->CALC_RSLT3);

    return 0;
}

int mbedtls_sm4_ctr_crypto(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    HAL_SM4_CTR_Crypt(ctx->iv, input, ilen, output);
    return 0;
}

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI_HARDWARE_ALT */