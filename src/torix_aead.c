/**
 * TORIX-AEAD Native C99 Implementation
 * ====================================
 * High-performance single-pass Authenticated Encryption with Associated Data.
 */

#include <stdlib.h>
#include <string.h>
#include "h512.h"
#include "torix_aead.h"

#define TAU_INIT 0x41
#define TAU_AD   0x01
#define TAU_ENC  0x02

static void init_aead_state(uint8_t state[8][8], const uint8_t key[32], const uint8_t nonce[16]) {
    uint8_t raw[64];
    memcpy(raw, key, 32);
    memcpy(raw + 32, nonce, 16);
    memset(raw + 48, 0, 15);
    raw[63] = TAU_INIT;

    memcpy(state, raw, 64);
    h512_permute_p16(state);

    uint8_t *st = (uint8_t *)state;
    for (int i = 0; i < 32; i++) {
        st[32 + i] ^= key[i];
    }
    h512_cleanse(raw, sizeof(raw));
}

static void process_associated_data(uint8_t state[8][8], const uint8_t *associated_data, size_t ad_len) {
    uint8_t *st = (uint8_t *)state;
    if (ad_len > 0 && associated_data) {
        size_t pad_len = 32 - (ad_len % 32);
        size_t total_ad = ad_len + pad_len;

        uint8_t *padded_ad = (uint8_t *)malloc(total_ad);
        if (padded_ad) {
            memcpy(padded_ad, associated_data, ad_len);
            if (pad_len == 1) {
                padded_ad[ad_len] = 0x81;
            } else {
                padded_ad[ad_len] = 0x01;
                if (pad_len > 2) {
                    memset(padded_ad + ad_len + 1, 0, pad_len - 2);
                }
                padded_ad[total_ad - 1] = 0x80;
            }

            for (size_t offset = 0; offset < total_ad; offset += 32) {
                for (size_t i = 0; i < 32; i++) {
                    st[i] ^= padded_ad[offset + i];
                }
                h512_permute_p8(state);
            }

            h512_cleanse(padded_ad, total_ad);
            free(padded_ad);
        }
    }
    st[63] ^= TAU_AD;
}

void torix_aead_encrypt(const uint8_t key[32],
                        const uint8_t nonce[16],
                        const uint8_t *plaintext,
                        size_t pt_len,
                        const uint8_t *associated_data,
                        size_t ad_len,
                        uint8_t *ciphertext,
                        uint8_t tag[32]) {
    uint8_t state[8][8];
    init_aead_state(state, key, nonce);
    process_associated_data(state, associated_data, ad_len);

    uint8_t *st = (uint8_t *)state;
    if (pt_len > 0 && plaintext && ciphertext) {
        size_t offset = 0;
        while (offset < pt_len) {
            size_t chunk_len = (pt_len - offset < 32) ? (pt_len - offset) : 32;

            for (size_t i = 0; i < chunk_len; i++) {
                ciphertext[offset + i] = plaintext[offset + i] ^ st[i];
                st[i] = ciphertext[offset + i];
            }

            if (chunk_len < 32) {
                st[chunk_len] ^= 0x01;
            }

            h512_permute_p8(state);
            offset += chunk_len;
        }
    }

    st[63] ^= TAU_ENC;

    for (int i = 0; i < 32; i++) {
        st[32 + i] ^= key[i];
    }
    h512_permute_p16(state);

    if (tag) {
        memcpy(tag, st, 32);
    }

    h512_cleanse(state, sizeof(state));
}

int torix_aead_decrypt(const uint8_t key[32],
                       const uint8_t nonce[16],
                       const uint8_t *ciphertext,
                       size_t ct_len,
                       const uint8_t tag[32],
                       const uint8_t *associated_data,
                       size_t ad_len,
                       uint8_t *plaintext) {
    if (!tag) return 0;

    uint8_t state[8][8];
    init_aead_state(state, key, nonce);
    process_associated_data(state, associated_data, ad_len);

    uint8_t *st = (uint8_t *)state;
    if (ct_len > 0 && ciphertext && plaintext) {
        size_t offset = 0;
        while (offset < ct_len) {
            size_t chunk_len = (ct_len - offset < 32) ? (ct_len - offset) : 32;

            for (size_t i = 0; i < chunk_len; i++) {
                plaintext[offset + i] = ciphertext[offset + i] ^ st[i];
                st[i] = ciphertext[offset + i];
            }

            if (chunk_len < 32) {
                st[chunk_len] ^= 0x01;
            }

            h512_permute_p8(state);
            offset += chunk_len;
        }
    }

    st[63] ^= TAU_ENC;

    for (int i = 0; i < 32; i++) {
        st[32 + i] ^= key[i];
    }
    h512_permute_p16(state);

    /* Constant-time tag verification */
    int valid = h512_verify_mac(st, tag, 32);

    if (!valid && plaintext && ct_len > 0) {
        /* Zeroize decrypted output upon tampering or authentication failure */
        h512_cleanse(plaintext, ct_len);
    }

    h512_cleanse(state, sizeof(state));
    return valid;
}
