/**
 * Project H-512 Reference C99 Implementation
 * ==========================================
 * Zero-allocation, high-speed cryptographic hash implementation.
 */

#include "h512.h"
#include "h512_constants.h"
#include <string.h>

#if defined(_MSC_VER)
    #define H512_BSWAP64(x) _byteswap_uint64(x)
#else
    #define H512_BSWAP64(x) __builtin_bswap64(x)
#endif

/* 64-Byte Cache Aligned State Union (Permits Strict Aliasing & SIMD Layout) */
typedef union {
    uint8_t  b[8][8];
    uint64_t u64[8];
    uint32_t u32[16];
} H512_ALIGN64 h512_state_t;

/* Bitwise Utilities */
static inline uint8_t rotl8(uint8_t x, int n) {
    n &= 7;
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

static inline uint8_t rotl4(uint8_t x, int n) {
    n &= 3;
    return (uint8_t)(((x << n) | (x >> (4 - n))) & 0x0F);
}

static inline uint64_t rotl_bytes64(uint64_t x, int r) {
    r &= 7;
    return r ? ((x >> (r * 8)) | (x << ((8 - r) * 8))) : x;
}

static inline void transpose8x8_inplace(uint8_t S[8][8]) {
    for (int r = 0; r < 7; r++) {
        for (int c = r + 1; c < 8; c++) {
            uint8_t tmp = S[r][c];
            S[r][c] = S[c][r];
            S[c][r] = tmp;
        }
    }
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
static inline void apply_mds_hyper_diffusion(h512_state_t *S) {
    /* Top 4 rows (columns 0..7) */
    uint64_t r0 = S->u64[0], r1 = S->u64[1], r2 = S->u64[2], r3 = S->u64[3];
    uint64_t t_top = r0 ^ r1 ^ r2 ^ r3;
    S->u64[0] = r0 ^ t_top ^ xtime_u64(r0 ^ r1);
    S->u64[1] = r1 ^ t_top ^ xtime_u64(r1 ^ r2);
    S->u64[2] = r2 ^ t_top ^ xtime_u64(r2 ^ r3);
    S->u64[3] = r3 ^ t_top ^ xtime_u64(r3 ^ r0);

    /* Bottom 4 rows (columns 0..7) */
    uint64_t r4 = S->u64[4], r5 = S->u64[5], r6 = S->u64[6], r7 = S->u64[7];
    uint64_t t_bot = r4 ^ r5 ^ r6 ^ r7;
    S->u64[4] = r4 ^ t_bot ^ xtime_u64(r4 ^ r5);
    S->u64[5] = r5 ^ t_bot ^ xtime_u64(r5 ^ r6);
    S->u64[6] = r6 ^ t_bot ^ xtime_u64(r6 ^ r7);
    S->u64[7] = r7 ^ t_bot ^ xtime_u64(r7 ^ r4);
}

/* Phase 12 Optimization: Register-Level Quadrant Swap (Zero Memcpy) */
static inline void swap_quadrants(h512_state_t *S) {
    for (int r = 0; r < 4; r++) {
        uint32_t tmp = S->u32[2 * r];
        S->u32[2 * r] = S->u32[2 * (r + 4) + 1];
        S->u32[2 * (r + 4) + 1] = tmp;

        tmp = S->u32[2 * r + 1];
        S->u32[2 * r + 1] = S->u32[2 * (r + 4)];
        S->u32[2 * (r + 4)] = tmp;
    }
}

/* Phase 6: Global Permutations (SWAR In-Place Word Permutation) */
static inline void apply_global_permutation(h512_state_t *S, int fam) {
    if (fam == 0) {
        /* Shift-Rows: row r shifted left by r */
        for (int r = 1; r < 8; r++) S->u64[r] = rotl_bytes64(S->u64[r], r);
    } else if (fam == 1) {
        /* Matrix Transposition: S[r][c] = S[c][r] */
        transpose8x8_inplace(S->b);
    } else if (fam == 2) {
        /* Shift-Rows + Transposition */
        for (int r = 1; r < 8; r++) S->u64[r] = rotl_bytes64(S->u64[r], r);
        transpose8x8_inplace(S->b);
    } else {
        /* Shift-Rows + Row-Reverse: shifted[r][7 - c] */
        for (int r = 0; r < 8; r++) S->u64[r] = H512_BSWAP64(rotl_bytes64(S->u64[r], r));
    }
}

/* Phase 7: Unified Round Engine (Zero Memcpy Dual-Buffer Interface) */
static void round_transform(const h512_state_t *S_in, h512_state_t *S_out, int rnd) {
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
    for (int r = 0; r < 8; r++) {
        int r_north = (r - 1) & 7;
        int r_south = (r + 1) & 7;
        for (int c = 0; c < 8; c++) {
            uint8_t north = S_in->b[r_north][c];
            uint8_t east  = S_in->b[r][(c + 1) & 7];
            uint8_t south = S_in->b[r_south][c];
            uint8_t west  = S_in->b[r][(c - 1) & 7];

            uint8_t context = S_in->b[r][c]
                            ^ rotl8(north, alpha)
                            ^ rotl8(east,  beta)
                            ^ rotl8(south, gamma)
                            ^ rotl8(west,  delta);

            S_out->b[r][c] = n_bio(context) ^ H512_RC[rnd][r][c];
        }
    }

    /* Pass 2: Involutive GF(2^8) Circulant MDS Hyper-Diffusion */
    apply_mds_hyper_diffusion(S_out);

    /* Pass 3: Regional Quadrant Swapping */
    if (fam == 1 || fam == 3) {
        swap_quadrants(S_out);
    }

    /* Pass 4: Global Permutation */
    apply_global_permutation(S_out, fam);
}

/* Phase 2 & 8: Compression Block Processing (Miyaguchi-Preneel with Zero-Copy Double-Buffering) */
static void compress_block_c(uint8_t S[8][8], const uint8_t block[64], uint64_t cumulative_bits) {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&H512_SBOX[0],   0, 3);
    __builtin_prefetch(&H512_SBOX[64],  0, 3);
    __builtin_prefetch(&H512_SBOX[128], 0, 3);
    __builtin_prefetch(&H512_SBOX[192], 0, 3);
#endif

    h512_state_t S_prev;
    memcpy(S_prev.b, S, 64);

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

    /* Zero-copy ping-pong double buffer */
    h512_state_t state_buf[2];
    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 8; c++) {
            state_buf[0].b[r][c] = S[r][c] ^ m_disp[r][c];
            if (r == c) {
                state_buf[0].b[r][c] ^= t_bytes[r];
            }
        }
    }

    /* Execute 16 rounds with ping-pong buffering (0 -> 1 -> 0 -> 1 ... -> 0) */
    for (int rnd = 0; rnd < 16; rnd++) {
        round_transform(&state_buf[rnd & 1], &state_buf[(rnd + 1) & 1], rnd);
    }

    /* 64-bit Miyaguchi-Preneel dual feedforward (state_buf[0] holds round 15 result) */
    uint64_t *S_u64 = (uint64_t *)S;
    for (int r = 0; r < 8; r++) {
        S_u64[r] = state_buf[0].u64[r] ^ S_prev.u64[r] ^ m_disp_u64[r];
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
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(v) : "memory");
#endif
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
    h512_state_t state_buf[2];
    memcpy(state_buf[0].b, S, 64);
    for (int rnd = 0; rnd < 16; rnd++) {
        round_transform(&state_buf[rnd & 1], &state_buf[(rnd + 1) & 1], rnd);
    }
    memcpy(S, state_buf[0].b, 64);
}

void h512_permute_p8(uint8_t S[8][8]) {
    h512_state_t state_buf[2];
    memcpy(state_buf[0].b, S, 64);
    for (int rnd = 0; rnd < 8; rnd++) {
        round_transform(&state_buf[rnd & 1], &state_buf[(rnd + 1) & 1], rnd);
    }
    memcpy(S, state_buf[0].b, 64);
}

