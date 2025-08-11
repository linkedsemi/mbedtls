#ifndef AES_ALT_H
#define AES_ALT_H
#include <stdint.h>

#if defined(CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI)
typedef struct mbedtls_aes_context {
}
mbedtls_aes_context;
#endif /* CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI */

#endif /* aes_alt.h*/