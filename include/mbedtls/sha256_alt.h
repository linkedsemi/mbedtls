#ifndef SHA256_ALT_H
#define SHA256_ALT_H
#include <stdint.h>
#include "mbedtls/private_access.h"

typedef struct mbedtls_sha256_context {
    bool start_calc_symbol;
}
mbedtls_sha256_context;

#endif /* sha256_alt.h */