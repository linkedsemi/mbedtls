#ifndef AES_ALT_H
#define AES_ALT_H
#include <stdint.h>

#if defined(CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI)
typedef struct mbedtls_aes_context {
    unsigned char key[32];
    unsigned int keybits;
}
mbedtls_aes_context;

typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context crypt; 
    mbedtls_aes_context tweak; 
} mbedtls_aes_xts_context;
#endif /* CONFIG_MBEDTLS_CIPHER_AES_LINKEDSEMI */

#endif /* aes_alt.h*/