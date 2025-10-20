#ifndef THREADING_ALT_H
#define THREADING_ALT_H
#include <zephyr/kernel.h>

#if defined(CONFIG_MBEDTLS_THREADING_LINKEDSEMI_ALT)
typedef struct {
    struct k_mutex k_mtx;
} mbedtls_threading_mutex_t;

void mbedtls_zephyr_threading_init(void);
#endif
#endif /* threading_alt.h */