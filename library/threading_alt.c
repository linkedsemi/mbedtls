#include <zephyr/kernel.h>
#include "../include/mbedtls/threading.h"

#if defined(CONFIG_MBEDTLS_THREADING_LINKEDSEMI_ALT)
static void zephyr_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    k_mutex_init(&mutex->k_mtx);
}

static void zephyr_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    (void)mutex;
}

static int zephyr_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    int ret = 0;

    if(k_mutex_lock(&mutex->k_mtx, K_FOREVER) !=0 )
    {
        ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return ret; 
}

static int zephyr_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    k_mutex_unlock(&mutex->k_mtx);

    return 0;
}

void mbedtls_zephyr_threading_init(void)
{
    #if defined(MBEDTLS_THREADING_ALT)
    mbedtls_threading_set_alt(zephyr_mbedtls_mutex_init,
                              zephyr_mbedtls_mutex_free,
                              zephyr_mbedtls_mutex_lock,
                              zephyr_mbedtls_mutex_unlock);
    #endif
}
#endif
