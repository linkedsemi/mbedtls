#ifndef THREADING_ALT_H
#define THREADING_ALT_H
#include <zephyr/kernel.h>

typedef struct {
    struct k_mutex k_mtx;
} mbedtls_threading_mutex_t;

void mbedtls_zephyr_threading_init(void);

#endif /* threading_alt.h */