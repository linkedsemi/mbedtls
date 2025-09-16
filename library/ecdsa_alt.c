/*
 *  Elliptic curve DSA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 */

#include "common.h"

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif

#include "mbedtls/platform.h"
#include "ls_hal_otbn.h"
#include "ls_msp_otbn.h"
#include "field_manipulate.h"
#include "reg_sysc_sec_cpu.h"
#include "platform.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/threading.h"

#include "ls_otbn_ecc.h"
#include "ls_hal_otbn.h"

#include <zephyr/irq.h>
#include <zephyr/kernel.h>

static struct k_sem wait_complete;
static mbedtls_threading_mutex_t doneLock;

ls_otbn_curve_id mbedtls_get_otbn_curve_id(mbedtls_ecp_group_id mbedtls_curve);
int get_curve_otbn_info(ls_otbn_curve_id curve, ecc_remote_addr *info);

void ls_otbn_cmd(enum HAL_OTBN_CMD cmd)
{
    if (LSOTBN->INTR_STATE)
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
    LSOTBN->INTR_ENABLE = OTBN_INTR_ENABLE_EN_MASK;
    LSOTBN->CMD = cmd;
    (void)k_sem_take(&wait_complete, K_FOREVER);
}

void reverse_buf(const uint8_t *input, uint8_t *output,uint16_t size)
{
    uint8_t tmp[size];
    if(input == NULL)
    {
        assert(0);
    }
    for(uint16_t i = 0; i < size; i++)
    {
        tmp[i] = input[size -i - 1];
    }
    memcpy(output,tmp,size);
}

int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_SIGN;
    uint8_t otbn_msg[100];
    uint8_t cc_buf[100];
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;
    ecc_remote_addr otbn_curve_info;
    if(!(grp->id == MBEDTLS_ECP_DP_BP384R1 || grp->id == MBEDTLS_ECP_DP_SECP256R1 || grp->id == MBEDTLS_ECP_DP_SM2))
    {
        printf(" the curve is not supported, curve id: %d",grp->id);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(grp->id),&otbn_curve_info) != 0)
    {
        printf("Otbn err state or curve don't adaptived");
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    f_rng(p_rng,cc_buf,use_size);
    if(use_size > 3 && cc_buf[0] == 0 && cc_buf[1] == 0 && cc_buf[2] == 0)
    {
        printf("trng error");
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    reverse_buf(cc_buf,cc_buf,use_size);
    if(grp->id == MBEDTLS_ECP_DP_SECP256R1)
        cc_buf[0] -= 33;
    if(HAL_OTBN_DMEM_Write(otbn_curve_info.remote_random_addr, (uint32_t *)cc_buf, otbn_curve_info.curve_size))
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    if(err == 0)
    {
        err |=HAL_OTBN_DMEM_Write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
        mbedtls_mpi_write_binary_le(d,cc_buf,n_size);
        err |=HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_d0, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        err |=HAL_OTBN_DMEM_Set(otbn_curve_info.remote_addr_d1,0,otbn_curve_info.curve_size);
        reverse_buf(buf,otbn_msg,use_size);
        err |=HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_msg, (uint32_t *)otbn_msg, otbn_curve_info.curve_size);
    }   
    if(err != 0)
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_r, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        mbedtls_mpi_read_binary_le(r,cc_buf,otbn_curve_info.curve_size);
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_s, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        mbedtls_mpi_read_binary_le(s,cc_buf,otbn_curve_info.curve_size);
    }

    return 0;
}   

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_VERIFY;
    uint8_t cc_buf[100];
    uint8_t r_x[100];
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;
    ecc_remote_addr otbn_curve_info;

    if(!(grp->id == MBEDTLS_ECP_DP_BP384R1 || grp->id == MBEDTLS_ECP_DP_SECP256R1 || grp->id == MBEDTLS_ECP_DP_SM2))
    {
        printf(" the curve is not supported, curve id: %d",grp->id);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(grp->id),&otbn_curve_info) != 0)
    {
        printf("Otbn err state or curve don't adaptived");
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    err = HAL_OTBN_DMEM_Write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
    if(err != 0)
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    err |= mbedtls_mpi_write_binary_le(&Q->X,cc_buf,n_size);
    err |= HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_qx, (uint32_t *)cc_buf, use_size);
    err |= mbedtls_mpi_write_binary_le(&Q->Y,cc_buf,n_size);
    err |= HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_qy, (uint32_t *)cc_buf, use_size);

    reverse_buf(buf,cc_buf,use_size);
    err |= HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_msg, (uint32_t *)cc_buf, use_size);

    err |= mbedtls_mpi_write_binary_le(s,cc_buf,n_size);
    err |= HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_s, (uint32_t *)cc_buf, use_size);
    err |= mbedtls_mpi_write_binary_le(r,cc_buf,n_size);
    err |= HAL_OTBN_DMEM_Write(otbn_curve_info.remote_addr_r, (uint32_t *)cc_buf, use_size);
    if(err != 0)
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_r_x, (uint32_t *)r_x, otbn_curve_info.curve_size);
        if(memcmp(r_x,cc_buf,otbn_curve_info.curve_size))
        {
            err = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        }
    }

    return err;
}


/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int err = 0;
    uint32_t mode = LS_OTBN_MODE_KEYGEN;
    uint8_t cc_buf[100];
    size_t n_size = (ctx->grp.nbits + 7) / 8;
    ecc_remote_addr otbn_curve_info;

    if(!(gid == MBEDTLS_ECP_DP_BP384R1 || gid == MBEDTLS_ECP_DP_SECP256R1 || gid == MBEDTLS_ECP_DP_SM2))
    {
        printf(" the curve is not supported, curve id: %d",gid);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    if(get_curve_otbn_info(mbedtls_get_otbn_curve_id(gid),&otbn_curve_info) != 0)
    {
        printf("Otbn err state or curve don't adaptived");
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    err = HAL_OTBN_DMEM_Write(otbn_curve_info.remote_mode_addr, (uint32_t *)&mode, 4);
    if(err != 0)
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    f_rng(p_rng,cc_buf,n_size);

    if(n_size > 3 && cc_buf[0] == 0 && cc_buf[1] == 0 && cc_buf[2] == 0)
    {
        printf("trng error");
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    reverse_buf(cc_buf,cc_buf,n_size);
    err = HAL_OTBN_DMEM_Write(otbn_curve_info.remote_random_addr, (uint32_t *)cc_buf, 32);//随机数种子宽度：32
    if(err != 0)
    {
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }

    ls_otbn_cmd(HAL_OTBN_CMD_EXECUTE);

    err = HAL_OTBN_Error_Bit_Get();
    if(err)
    {
        //printf("errors detected during an operation 0x%x\r\n",err);
        return MBEDTLS_ERR_ECP_IN_PROGRESS;
    }
    else
    {
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_d0, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        mbedtls_mpi_read_binary_le(&ctx->d,cc_buf,otbn_curve_info.curve_size);
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_qx, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        mbedtls_mpi_read_binary_le(&ctx->Q.X,cc_buf,otbn_curve_info.curve_size);
        HAL_OTBN_DMEM_Read(otbn_curve_info.remote_addr_qy, (uint32_t *)cc_buf, otbn_curve_info.curve_size);
        mbedtls_mpi_read_binary_le(&ctx->Q.Y,cc_buf,otbn_curve_info.curve_size);
    }
    return err;
}


ls_otbn_curve_id mbedtls_get_otbn_curve_id(mbedtls_ecp_group_id mbedtls_curve)
{
    ls_otbn_curve_id id = LS_OTBN_CURVE_MAX;
    switch (mbedtls_curve)
    {
    case MBEDTLS_ECP_DP_SECP256R1:
        id = LS_OTBN_CURVE_ECC_P256;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        id = LS_OTBN_CURVE_ECC_P384;
        break;
    case MBEDTLS_ECP_DP_SM2:
        id = LS_OTBN_CURVE_SM2;
        break;
    default:
        break;
    }

    return id;
}

void mbedtls_LS_OTBN_IRQHandler()
{
    if (LSOTBN->INTR_STATE)
    {
        LSOTBN->INTR_STATE = OTBN_INTR_STATE_DONE_MASK;
        k_sem_give(&wait_complete);

    }
}

extern void HAL_OTBN_SYSC_IRQHandler(void);
void mbedtls_ls_otbn_moudle_init(void)
{
#if defined(CONFIG_MBEDTLS)
    uint32_t EDN_URND_BUS_IN = 0;
    REG_FIELD_WR(SYSC_SEC_CPU->INTR_CTRL_INTR_MSK, SYSC_SEC_CPU_I_EDN_URND_REQ, 0);
    SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_CLR_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_CLR_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_SRST[1] = SYSC_SEC_CPU_SRST_SET_OTBN_MASK;
    SYSC_SEC_CPU->PD_CPU_CLKG[1] = SYSC_SEC_CPU_CLKG_SET_OTBN_MASK;
    for (uint8_t i = 0; i < 16; i++)
    {
        while (!REG_FIELD_RD(SYSC_SEC_CPU->OTBN_INTR_RAW, SYSC_SEC_CPU_I_EDN_URND_REQ)) ;
        SYSC_SEC_CPU->EDN_URND_BUS = ++EDN_URND_BUS_IN;
        REG_FIELD_WR(SYSC_SEC_CPU->OTBN_CTRL2, SYSC_SEC_CPU_EDN_URND_ACK, 1);
        REG_FIELD_WR(SYSC_SEC_CPU->OTBN_CTRL2, SYSC_SEC_CPU_EDN_URND_ACK, 0);
        SYSC_SEC_CPU->INTR_CLR_MSK = SYSC_SEC_CPU_I_EDN_URND_REQ_MASK;
    }
    SYSC_SEC_CPU->INTR_CLR_MSK = FIELD_BUILD(SYSC_SEC_CPU_I_EDN_RND_REQ, 1) |
                            FIELD_BUILD(SYSC_SEC_CPU_I_EDN_URND_REQ, 1) |
                            FIELD_BUILD(SYSC_SEC_CPU_I_OTBN_OTP_REQ, 1);
    SYSC_SEC_CPU->INTR_CTRL_INTR_MSK = FIELD_BUILD(SYSC_SEC_CPU_I_EDN_RND_REQ, 1) |
                              FIELD_BUILD(SYSC_SEC_CPU_I_EDN_URND_REQ, 1) |
                              FIELD_BUILD(SYSC_SEC_CPU_I_OTBN_OTP_REQ, 1);


    IRQ_CONNECT(OTBN_SYSC_IRQN, 3, HAL_OTBN_SYSC_IRQHandler,NULL, 0);
    irq_enable(OTBN_SYSC_IRQN);
    IRQ_CONNECT(OBTN_IRQN, 3, mbedtls_LS_OTBN_IRQHandler,NULL, 0);
    irq_enable(OBTN_IRQN);

    mbedtls_mutex_init(&doneLock);
    k_sem_init(&wait_complete,0,1);
#else
    // HAL_LSOTBN_MSP_Init();
#endif
}

void mbedtls_ls_otbn_moudle_deinit(void)
{
    HAL_LSOTBN_MSP_DeInit();
}


#endif /* MBEDTLS_ECDSA_C */
