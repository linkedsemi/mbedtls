#ifndef SHA256_ALT_H
#define SHA256_ALT_H
#include <stdint.h>
#include "mbedtls/private_access.h"

#if defined(CONFIG_MBEDTLS_SHA256_LINKEDSEMI)
typedef struct mbedtls_sha256_context {
    bool start_calc_symbol;
}
mbedtls_sha256_context;
#endif /* CONFIG_MBEDTLS_SHA256_LINKEDSEMI */

#endif /* sha256_alt.h */