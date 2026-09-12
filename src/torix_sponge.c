/**
 * TORIX-Sponge Native C99 Implementation
 * =====================================
 * High-performance Multi-Rate Duplex Cryptographic Sponge & XOF.
 */

#include <stdlib.h>
#include <string.h>
#include "h512.h"
#include "h512_constants.h"
#include "torix_sponge.h"

void torix_sponge_init(torix_sponge_ctx *ctx, size_t rate, size_t capacity, uint8_t domain_tag) {
    if (!ctx) return;
    if (rate + capacity != 64) return;

    ctx->rate = rate;
    ctx->capacity = capacity;
    ctx->domain_tag = domain_tag;

    memcpy(ctx->state, H512_IV, 64);
    ctx->state[0][0] ^= (uint8_t)rate;
    ctx->state[0][1] ^= (uint8_t)capacity;
    ctx->state[7][7] ^= domain_tag;

    h512_permute_p16(ctx->state);
}

void torix_sponge_absorb(torix_sponge_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx) return;
    size_t pad_len = ctx->rate - (len % ctx->rate);
    size_t total_len = len + pad_len;

    uint8_t *padded = (uint8_t *)malloc(total_len);
    if (!padded) return;

    if (len > 0 && data) {
        memcpy(padded, data, len);
    }

    if (pad_len == 1) {
        padded[len] = 0x81;
    } else {
        padded[len] = 0x01;
        if (pad_len > 2) {
            memset(padded + len + 1, 0, pad_len - 2);
        }
        padded[total_len - 1] = 0x80;
    }

    uint8_t *raw_state = (uint8_t *)ctx->state;
    for (size_t offset = 0; offset < total_len; offset += ctx->rate) {
        for (size_t i = 0; i < ctx->rate; i++) {
            raw_state[i] ^= padded[offset + i];
        }
        h512_permute_p16(ctx->state);
    }

    h512_cleanse(padded, total_len);
    free(padded);
}

void torix_sponge_squeeze(torix_sponge_ctx *ctx, uint8_t *out, size_t out_len) {
    if (!ctx || !out || out_len == 0) return;

    size_t produced = 0;
    uint8_t *raw_state = (uint8_t *)ctx->state;

    while (produced < out_len) {
        size_t remaining = out_len - produced;
        size_t take = (remaining < ctx->rate) ? remaining : ctx->rate;

        memcpy(out + produced, raw_state, take);
        produced += take;

        if (produced < out_len) {
            h512_permute_p16(ctx->state);
        }
    }
}

void torix_sponge_duplex(torix_sponge_ctx *ctx, const uint8_t *data_in, size_t in_len, uint8_t *out, size_t out_len) {
    if (!ctx) return;
    if (in_len > ctx->rate) return;

    uint8_t *raw_state = (uint8_t *)ctx->state;
    if (data_in && in_len > 0) {
        for (size_t i = 0; i < in_len; i++) {
            raw_state[i] ^= data_in[i];
        }
    }

    raw_state[63] ^= 0x01;
    h512_permute_p16(ctx->state);

    if (out && out_len > 0) {
        torix_sponge_squeeze(ctx, out, out_len);
    }
}

void torix_xof(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, int post_quantum) {
    size_t rate = post_quantum ? 16 : 32;
    size_t capacity = post_quantum ? 48 : 32;

    torix_sponge_ctx ctx;
    torix_sponge_init(&ctx, rate, capacity, 0x53);
    torix_sponge_absorb(&ctx, data, len);
    torix_sponge_squeeze(&ctx, out, out_len);
    h512_cleanse(&ctx, sizeof(ctx));
}
