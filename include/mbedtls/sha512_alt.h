#ifndef SHA512_ALT_H
#define SHA512_ALT_H
#include <stdint.h>

#if defined(CONFIG_MBEDTLS_SHA512_LINKEDSEMI)
typedef struct mbedtls_sha512_context {
    bool start_calc_symbol;
    bool is384;
}
mbedtls_sha512_context;
#endif /* CONFIG_MBEDTLS_SHA512_LINKEDSEMI */

#endif /* sha512_alt.h */