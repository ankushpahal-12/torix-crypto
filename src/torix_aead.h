/**
 * TORIX-AEAD Native C99 Header
 * ============================
 * Authenticated Encryption with Associated Data (AEAD).
 * Single-pass high-speed confidentiality and integrity engine.
 */

#ifndef TORIX_AEAD_H
#define TORIX_AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "h512.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TORIX_AEAD_KEY_LEN   32  /* 256 bits */
#define TORIX_AEAD_NONCE_LEN 16  /* 128 bits */
#define TORIX_AEAD_TAG_LEN   32  /* 256 bits */

void torix_aead_encrypt(const uint8_t key[32],
                        const uint8_t nonce[16],
                        const uint8_t *plaintext,
                        size_t pt_len,
                        const uint8_t *associated_data,
                        size_t ad_len,
                        uint8_t *ciphertext,
                        uint8_t tag[32]);

int torix_aead_decrypt(const uint8_t key[32],
                       const uint8_t nonce[16],
                       const uint8_t *ciphertext,
                       size_t ct_len,
                       const uint8_t tag[32],
                       const uint8_t *associated_data,
                       size_t ad_len,
                       uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* TORIX_AEAD_H */
