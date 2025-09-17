#ifndef __MBEDTLS_LS_OTBN__
#define __MBEDTLS_LS_OTBN__



#if defined(CONFIG_MBEDTLS)


extern void HAL_OTBN_SYSC_IRQHandler(void);
static void ls_zephyr_mbedtls_otbn_init(void (*irq_func)(void))
{
    uint32_t key;
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

    key = irq_lock();
    IRQ_CONNECT(OTBN_SYSC_IRQN, 3, HAL_OTBN_SYSC_IRQHandler,NULL, 0);
    irq_enable(OTBN_SYSC_IRQN);
    IRQ_CONNECT(OBTN_IRQN, 3, mbedtls_LS_OTBN_IRQHandler,NULL, 0);
    irq_enable(OBTN_IRQN);
    irq_unlock(key);
}



#endif

#endif






