/**
 * TORIX-Sponge Native C99 Header
 * ==============================
 * Multi-Rate Duplex Cryptographic Sponge & XOF Engine.
 */

#ifndef TORIX_SPONGE_H
#define TORIX_SPONGE_H

#include <stddef.h>
#include <stdint.h>
#include "h512.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t state[8][8];
    size_t rate;
    size_t capacity;
    uint8_t domain_tag;
} torix_sponge_ctx;

void torix_sponge_init(torix_sponge_ctx *ctx, size_t rate, size_t capacity, uint8_t domain_tag);
void torix_sponge_absorb(torix_sponge_ctx *ctx, const uint8_t *data, size_t len);
void torix_sponge_squeeze(torix_sponge_ctx *ctx, uint8_t *out, size_t out_len);
void torix_sponge_duplex(torix_sponge_ctx *ctx, const uint8_t *data_in, size_t in_len, uint8_t *out, size_t out_len);

/* One-shot XOF */
void torix_xof(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, int post_quantum);

#ifdef __cplusplus
}
#endif

#endif /* TORIX_SPONGE_H */
