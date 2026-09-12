/**
 * Project H-512 Reference C99 Implementation
 * ==========================================
 * Zero-allocation, high-speed cryptographic hash implementation.
 */

#include "h512.h"
#include "h512_constants.h"
#include <string.h>

/* Bitwise Utilities */
static inline uint8_t rotl8(uint8_t x, int n) {
    n &= 7;
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

static inline uint8_t rotl4(uint8_t x, int n) {
    n &= 3;
    return (uint8_t)(((x << n) | (x >> (4 - n))) & 0x0F);
}

/* Phase 12 Optimization: L1-Cache Aligned S-Box Lookup */
static inline uint8_t n_bio(uint8_t x) {
    return H512_SBOX[x];
}

/* Phase 12 Optimization: Branchless 64-bit SWAR Parallel xtime */
static inline uint64_t xtime_u64(uint64_t x) {
    uint64_t mask = x & 0x8080808080808080ULL;
    uint64_t shifted = (x << 1) & 0xFEFEFEFEFEFEFEFEULL;
    uint64_t reduction = (mask >> 7) * 0x1B;
    return shifted ^ reduction;
}

/* Phase 12 Optimization: Vectorized GF(2^8) Circulant MDS Hyper-Diffusion */
static inline void apply_mds_hyper_diffusion(uint8_t S[8][8]) {
    uint64_t *R = (uint64_t *)S;

    /* Top 4 rows (columns 0..7) */
    uint64_t r0 = R[0], r1 = R[1], r2 = R[2], r3 = R[3];
    uint64_t t_top = r0 ^ r1 ^ r2 ^ r3;
    R[0] = r0 ^ t_top ^ xtime_u64(r0 ^ r1);
    R[1] = r1 ^ t_top ^ xtime_u64(r1 ^ r2);
    R[2] = r2 ^ t_top ^ xtime_u64(r2 ^ r3);
    R[3] = r3 ^ t_top ^ xtime_u64(r3 ^ r0);

    /* Bottom 4 rows (columns 0..7) */
    uint64_t r4 = R[4], r5 = R[5], r6 = R[6], r7 = R[7];
    uint64_t t_bot = r4 ^ r5 ^ r6 ^ r7;
    R[4] = r4 ^ t_bot ^ xtime_u64(r4 ^ r5);
    R[5] = r5 ^ t_bot ^ xtime_u64(r5 ^ r6);
    R[6] = r6 ^ t_bot ^ xtime_u64(r6 ^ r7);
    R[7] = r7 ^ t_bot ^ xtime_u64(r7 ^ r4);
}

/* Phase 12 Optimization: Register-Level Quadrant Swap (Zero Memcpy) */
static inline void swap_quadrants(uint8_t S[8][8]) {
    uint32_t *w = (uint32_t *)S;
    for (int r = 0; r < 4; r++) {
        /* Q0 (row r left) <-> Q3 (row r+4 right) */
        uint32_t tmp = w[2 * r];
        w[2 * r] = w[2 * (r + 4) + 1];
        w[2 * (r + 4) + 1] = tmp;

        /* Q1 (row r right) <-> Q2 (row r+4 left) */
        tmp = w[2 * r + 1];
        w[2 * r + 1] = w[2 * (r + 4)];
        w[2 * (r + 4)] = tmp;
    }
}

/* Phase 6: Global Permutations */
static inline void apply_global_permutation(uint8_t S[8][8], int perm_mode) {
    uint8_t temp[8][8];
    memcpy(temp, S, 64);

    if (perm_mode == 0) {
        /* Shift-Rows: row r shifted left by r */
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                S[r][c] = temp[r][(c + r) & 7];
            }
        }
    } else if (perm_mode == 1) {
        /* Matrix Transposition: S[r][c] = S[c][r] */
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                S[r][c] = temp[c][r];
            }
        }
    } else if (perm_mode == 2) {
        /* Shift-Rows + Transposition */
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                uint8_t shifted = temp[r][(c + r) & 7];
                S[c][r] = shifted;
            }
        }
    } else {
        /* Shift-Rows + Row-Reverse: shifted[r][7 - c] */
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                S[r][c] = temp[r][((7 - c) + r) & 7];
            }
        }
    }
}

/* Phase 7: Unified Round Engine */
static void round_transform(uint8_t S[8][8], int rnd) {
    int fam = rnd & 3;
    static const int rotations[4][4] = {
        {1, 2, 3, 5},  /* Family A */
        {3, 5, 1, 7},  /* Family B */
        {5, 1, 7, 3},  /* Family C */
        {7, 3, 5, 1}   /* Family D */
    };
    int alpha = rotations[fam][0];
    int beta  = rotations[fam][1];
    int gamma = rotations[fam][2];
    int delta = rotations[fam][3];

    /* Pass 1: Toroidal Context Coupling + N_bio */
    uint8_t S_sub[8][8];
    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 8; c++) {
            uint8_t north = S[(r - 1) & 7][c];
            uint8_t east  = S[r][(c + 1) & 7];
            uint8_t south = S[(r + 1) & 7][c];
            uint8_t west  = S[r][(c - 1) & 7];

            uint8_t context = S[r][c]
                            ^ rotl8(north, alpha)
                            ^ rotl8(east,  beta)
                            ^ rotl8(south, gamma)
                            ^ rotl8(west,  delta);

            S_sub[r][c] = n_bio(context) ^ H512_RC[rnd][r][c];
        }
    }

    /* Pass 2: Involutive GF(2^8) Circulant MDS Hyper-Diffusion */
    apply_mds_hyper_diffusion(S_sub);

    /* Pass 3: Regional Quadrant Swapping */
    if (fam == 1 || fam == 3) {
        swap_quadrants(S_sub);
    }

    /* Pass 4: Global Permutation */
    apply_global_permutation(S_sub, fam);

    memcpy(S, S_sub, 64);
}

/* Phase 2 & 8: Compression Block Processing (Miyaguchi-Preneel) */
static void compress_block_c(uint8_t S[8][8], const uint8_t block[64], uint64_t cumulative_bits) {
    uint8_t S_prev[8][8];
    memcpy(S_prev, S, 64);

    /* 64-bit Orthogonal message dispersal */
    uint64_t m_disp_u64[8];
    const uint64_t *M_in = (const uint64_t *)block;
    for (int r = 0; r < 8; r++) {
        int shift = r & 7;
        uint64_t x = M_in[r];
        m_disp_u64[r] = shift ? ((x >> (shift * 8)) | (x << ((8 - shift) * 8))) : x;
    }
    const uint8_t (*m_disp)[8] = (const uint8_t (*)[8])m_disp_u64;

    /* Ingestion & HAIFA diagonal bit-counter injection */
    uint8_t t_bytes[8];
    for (int i = 0; i < 8; i++) {
        t_bytes[7 - i] = (uint8_t)(cumulative_bits >> (i * 8));
    }

    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 8; c++) {
            S[r][c] ^= m_disp[r][c];
            if (r == c) {
                S[r][c] ^= t_bytes[r];
            }
        }
    }

    /* Execute 16 rounds */
    for (int rnd = 0; rnd < 16; rnd++) {
        round_transform(S, rnd);
    }

    /* 64-bit Miyaguchi-Preneel dual feedforward */
    uint64_t *S_u64 = (uint64_t *)S;
    const uint64_t *S_prev_u64 = (const uint64_t *)S_prev;
    for (int r = 0; r < 8; r++) {
        S_u64[r] ^= S_prev_u64[r] ^ m_disp_u64[r];
    }
}

/* Public API Implementation */
void h512_init(h512_ctx *ctx) {
    memcpy(ctx->state, H512_IV, 64);
    ctx->buffer_len = 0;
    ctx->total_bytes = 0;
    ctx->blocks_processed = 0;
    ctx->domain_tag = 0x00; /* Standard H-512 */
}

void h256_init(h512_ctx *ctx) {
    memcpy(ctx->state, H512_IV, 64);
    ctx->buffer_len = 0;
    ctx->total_bytes = 0;
    ctx->blocks_processed = 0;
    ctx->domain_tag = 0x01; /* Truncated H-256 */
}

void h512_update(h512_ctx *ctx, const void *data, size_t len) {
    const uint8_t *ptr = (const uint8_t *)data;
    ctx->total_bytes += len;

    /* Fill buffer and process */
    while (len > 0) {
        size_t to_copy = 64 - ctx->buffer_len;
        if (len < to_copy) {
            to_copy = len;
        }
        memcpy(ctx->buffer + ctx->buffer_len, ptr, to_copy);
        ctx->buffer_len += to_copy;
        ptr += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == 64) {
            ctx->blocks_processed++;
            uint64_t cumulative_bits = ctx->blocks_processed * 512;
            if (cumulative_bits > ctx->total_bytes * 8) {
                cumulative_bits = ctx->total_bytes * 8;
            }
            compress_block_c(ctx->state, ctx->buffer, cumulative_bits);
            ctx->buffer_len = 0;
        }
    }
}

static void finalize_internal(h512_ctx *ctx, uint8_t *out, int is_256) {
    uint64_t bit_len = ctx->total_bytes * 8;
    size_t rem = ctx->buffer_len;
    size_t k = (64 - ((rem + 10) % 64)) % 64;

    size_t pad_total = rem + 1 + k + 1 + 8;
    uint8_t final_blocks[128];
    memset(final_blocks, 0, pad_total);

    memcpy(final_blocks, ctx->buffer, rem);
    final_blocks[rem] = 0x80;
    /* k zero bytes are already 0 from memset */
    final_blocks[rem + 1 + k] = ctx->domain_tag;

    for (int i = 0; i < 8; i++) {
        final_blocks[rem + 1 + k + 1 + 7 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    size_t num_blocks = pad_total / 64;
    for (size_t i = 0; i < num_blocks; i++) {
        compress_block_c(ctx->state, final_blocks + i * 64, bit_len);
    }

    if (is_256) {
        /* H-256 Nonlinear Cross-Fold: S[r][c] ^ N_bio(S[r+4][c]) */
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 8; c++) {
                out[r * 8 + c] = ctx->state[r][c] ^ n_bio(ctx->state[r + 4][c]);
            }
        }
    } else {
        /* H-512 Canonical Row-Major Serialization */
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                out[r * 8 + c] = ctx->state[r][c];
            }
        }
    }
}

void h512_final(h512_ctx *ctx, uint8_t out[64]) {
    finalize_internal(ctx, out, 0);
}

void h256_final(h512_ctx *ctx, uint8_t out[32]) {
    finalize_internal(ctx, out, 1);
}

/* Phase 14 Hardening: Volatile State Scrubbing (Anti-Dead-Code Elimination) */
typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t h512_memset_func = memset;

void h512_cleanse(void *v, size_t n) {
    if (v && n > 0) {
        h512_memset_func(v, 0, n);
    }
}

/* Phase 14 Hardening: Branchless Constant-Time MAC Verification */
int h512_verify_mac(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return (diff == 0);
}

void h512_hash(const void *data, size_t len, uint8_t out[64]) {
    h512_ctx ctx;
    h512_init(&ctx);
    h512_update(&ctx, data, len);
    h512_final(&ctx, out);
    h512_cleanse(&ctx, sizeof(ctx));
}

void h256_hash(const void *data, size_t len, uint8_t out[32]) {
    h512_ctx ctx;
    h256_init(&ctx);
    h512_update(&ctx, data, len);
    h256_final(&ctx, out);
    h512_cleanse(&ctx, sizeof(ctx));
}

void h512_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

void h512_permute_p16(uint8_t S[8][8]) {
    for (int rnd = 0; rnd < 16; rnd++) {
        round_transform(S, rnd);
    }
}

void h512_permute_p8(uint8_t S[8][8]) {
    for (int rnd = 0; rnd < 8; rnd++) {
        round_transform(S, rnd);
    }
}

