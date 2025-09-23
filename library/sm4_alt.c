#include "mbedtls/platform_util.h"
#include <string.h>
#include "mbedtls/sm4_alt.h"

#if defined(CONFIG_MBEDTLS_SM4_LINKEDSEMI)

#include <ls_hal_sm4.h>

#define SM4_IV_SIZE 16

void mbedtls_sm4_init(mbedtls_sm4_context *ctx)
{
#if CONFIG_SOC_LS1010
    HAL_SM4_Init();
#elif CONFIG_SOC_LSQSH
    #if CONFIG_SM4_CLOCK_RESET
        #include "reg_sysc_sec_cpu.h"
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_CALC_SM4_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_CALC_SM4_MASK;
        SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_CALC_SM4_MASK;
        SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_CALC_SM4_MASK;
    #endif
#endif
}

void mbedtls_sm4_free(mbedtls_sm4_context *ctx)
{
#if CONFIG_SOC_LS1010
    HAL_SM4_DeInit();
#elif CONFIG_SOC_LSQSH
    #if CONFIG_SM4_CLOCK_RESET
        #include "reg_sysc_sec_cpu.h"
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
    return HAL_SM4_Encrypt(input, output, ilen);
}

int mbedtls_sm4_ecb_decrypt(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    return HAL_SM4_Decrypt(input, output, ilen);
}

int mbedtls_sm4_ctr_crypto(mbedtls_sm4_context *ctx, unsigned char* output, const unsigned char* input, size_t ilen)
{
    HAL_SM4_CTR_Crypt(ctx->iv, input, ilen, output);
    return 0;
}

#endif /* CONFIG_MBEDTLS_SM4_LINKEDSEMI */