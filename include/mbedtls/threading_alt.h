#ifndef THREADING_ALT_H
#define THREADING_ALT_H
#include <zephyr/kernel.h>

#if defined(CONFIG_SOC_LSQSH)||defined(CONFIG_SOC_LS1010)
typedef struct {
    struct k_mutex k_mtx;
} mbedtls_threading_mutex_t;

void mbedtls_zephyr_threading_init(void);
#endif /* CONFIG_MBEDTLS_SHA256_LINKEDSEMI || CONFIG_MBEDTLS_SHA512_LINKEDSEMI*/

#endif /* threading_alt.h */