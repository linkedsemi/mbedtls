#ifndef SHA512_ALT_H
#define SHA512_ALT_H
#include <stdint.h>
#include <stdbool.h>
#if defined(MBEDTLS_SHA512_ALT)
typedef struct mbedtls_sha512_context {
    bool start_calc_symbol;
    bool is384;
}
mbedtls_sha512_context;
#endif /* MBEDTLS_SHA512_ALT */

#endif /* sha512_alt.h */