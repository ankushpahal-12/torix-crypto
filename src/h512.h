/**
 * Project H-512 Reference C99 Implementation
 * ==========================================
 * High-performance, zero-allocation cryptographic hash engine.
 */

#ifndef H512_H
#define H512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t state[8][8];
    uint8_t buffer[64];
    size_t  buffer_len;
    uint64_t total_bytes;
    uint64_t blocks_processed;
    uint8_t domain_tag;
} h512_ctx;

/* Stateful Streaming API */
void h512_init(h512_ctx *ctx);
void h256_init(h512_ctx *ctx);
void h512_update(h512_ctx *ctx, const void *data, size_t len);
void h512_final(h512_ctx *ctx, uint8_t out[64]);
void h256_final(h512_ctx *ctx, uint8_t out[32]);

/* One-shot API */
void h512_hash(const void *data, size_t len, uint8_t out[64]);
void h256_hash(const void *data, size_t len, uint8_t out[32]);

/* Helper for Hex formatting */
void h512_to_hex(const uint8_t *bytes, size_t len, char *hex_out);

/* Phase 14 Hardening: Constant-time MAC Verification & Volatile State Cleansing */
int  h512_verify_mac(const uint8_t *a, const uint8_t *b, size_t len);
void h512_cleanse(void *v, size_t n);

/* Permutation Primitives for Sponge & AEAD */
void h512_permute_p16(uint8_t S[8][8]);
void h512_permute_p8(uint8_t S[8][8]);

#ifdef __cplusplus
}
#endif

#endif /* H512_H */
