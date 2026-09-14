/**
 * Project H-512 / TORIX-512 Unified Cryptographic Engine Implementation
 * ======================================================================
 * Complete, single-file native C99/AVX2 cryptographic engine:
 * 1. TORIX-512 & TORIX-256 HAIFA Hash Functions
 * 2. 4-Way AVX2 Inter-Chunk SIMD Vectorization Engine
 * 3. Parallel Binary Merkle Tree Hasher (BLAKE3-style O(log N) Streaming)
 * 4. Multi-Rate Duplex Cryptographic Sponge & XOF Engine
 * 5. Single-Pass Authenticated Encryption with Associated Data (AEAD)
 * 6. Production Constant-Time MAC Verification & Volatile State Cleansing
 */

#if defined(__GNUC__) || defined(__clang__)
    #pragma GCC push_options
    #pragma GCC target("avx2")
#endif

#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h512.h"
#include "h512_constants.h"

#if defined(_MSC_VER)
    #include <intrin.h>
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

/* ========================================================================= */
/* SECTION 1: BITWISE & LINEAR ALGEBRA UTILITIES                             */
/* ========================================================================= */
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

static inline uint8_t n_bio(uint8_t x) {
    return H512_SBOX[x];
}

/* Branchless 64-bit SWAR Parallel xtime */
static inline uint64_t xtime_u64(uint64_t x) {
    uint64_t mask = x & 0x8080808080808080ULL;
    uint64_t shifted = (x << 1) & 0xFEFEFEFEFEFEFEFEULL;
    uint64_t reduction = (mask >> 7) * 0x1B;
    return shifted ^ reduction;
}

/* Vectorized GF(2^8) Circulant MDS Hyper-Diffusion */
static inline void apply_mds_hyper_diffusion(h512_state_t *S) {
    /* Top 4 rows */
    uint64_t r0 = S->u64[0], r1 = S->u64[1], r2 = S->u64[2], r3 = S->u64[3];
    uint64_t t_top = r0 ^ r1 ^ r2 ^ r3;
    S->u64[0] = r0 ^ t_top ^ xtime_u64(r0 ^ r1);
    S->u64[1] = r1 ^ t_top ^ xtime_u64(r1 ^ r2);
    S->u64[2] = r2 ^ t_top ^ xtime_u64(r2 ^ r3);
    S->u64[3] = r3 ^ t_top ^ xtime_u64(r3 ^ r0);

    /* Bottom 4 rows */
    uint64_t r4 = S->u64[4], r5 = S->u64[5], r6 = S->u64[6], r7 = S->u64[7];
    uint64_t t_bot = r4 ^ r5 ^ r6 ^ r7;
    S->u64[4] = r4 ^ t_bot ^ xtime_u64(r4 ^ r5);
    S->u64[5] = r5 ^ t_bot ^ xtime_u64(r5 ^ r6);
    S->u64[6] = r6 ^ t_bot ^ xtime_u64(r6 ^ r7);
    S->u64[7] = r7 ^ t_bot ^ xtime_u64(r7 ^ r4);
}

/* Register-Level Quadrant Swap */
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

/* Global Permutations */
static inline void apply_global_permutation(h512_state_t *S, int fam) {
    if (fam == 0) {
        for (int r = 1; r < 8; r++) S->u64[r] = rotl_bytes64(S->u64[r], r);
    } else if (fam == 1) {
        transpose8x8_inplace(S->b);
    } else if (fam == 2) {
        for (int r = 1; r < 8; r++) S->u64[r] = rotl_bytes64(S->u64[r], r);
        transpose8x8_inplace(S->b);
    } else {
        for (int r = 0; r < 8; r++) S->u64[r] = H512_BSWAP64(rotl_bytes64(S->u64[r], r));
    }
}

/* Unified Round Engine */
static void round_transform(const h512_state_t *S_in, h512_state_t *S_out, int rnd) {
    int fam = rnd & 3;
    static const int rotations[4][4] = {
        {1, 2, 3, 5},
        {3, 5, 1, 7},
        {5, 1, 7, 3},
        {7, 3, 5, 1}
    };
    int alpha = rotations[fam][0];
    int beta  = rotations[fam][1];
    int gamma = rotations[fam][2];
    int delta = rotations[fam][3];

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

    apply_mds_hyper_diffusion(S_out);
    if (fam == 1 || fam == 3) swap_quadrants(S_out);
    apply_global_permutation(S_out, fam);
}

/* Compression Block Processing (Miyaguchi-Preneel with Zero-Copy Double-Buffering) */
static void compress_block_c(uint8_t S[8][8], const uint8_t block[64], uint64_t cumulative_bits) {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&H512_SBOX[0],   0, 3);
    __builtin_prefetch(&H512_SBOX[64],  0, 3);
    __builtin_prefetch(&H512_SBOX[128], 0, 3);
    __builtin_prefetch(&H512_SBOX[192], 0, 3);
#endif

    h512_state_t S_prev;
    memcpy(S_prev.b, S, 64);

    uint64_t m_disp_u64[8];
    const uint64_t *M_in = (const uint64_t *)block;
    for (int r = 0; r < 8; r++) {
        int shift = r & 7;
        uint64_t x = M_in[r];
        m_disp_u64[r] = shift ? ((x >> (shift * 8)) | (x << ((8 - shift) * 8))) : x;
    }
    const uint8_t (*m_disp)[8] = (const uint8_t (*)[8])m_disp_u64;

    uint8_t t_bytes[8];
    for (int i = 0; i < 8; i++) {
        t_bytes[7 - i] = (uint8_t)(cumulative_bits >> (i * 8));
    }

    h512_state_t state_buf[2];
    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 8; c++) {
            state_buf[0].b[r][c] = S[r][c] ^ m_disp[r][c];
            if (r == c) state_buf[0].b[r][c] ^= t_bytes[r];
        }
    }

    for (int rnd = 0; rnd < 16; rnd++) {
        round_transform(&state_buf[rnd & 1], &state_buf[(rnd + 1) & 1], rnd);
    }

    uint64_t *S_u64 = (uint64_t *)S;
    for (int r = 0; r < 8; r++) {
        S_u64[r] = state_buf[0].u64[r] ^ S_prev.u64[r] ^ m_disp_u64[r];
    }
}

/* ========================================================================= */
/* SECTION 2: PUBLIC HASHING API (H-512 & H-256)                             */
/* ========================================================================= */
void h512_init_tag(h512_ctx *ctx, uint8_t domain_tag) {
    memcpy(ctx->state, H512_IV, 64);
    ctx->buffer_len = 0;
    ctx->total_bytes = 0;
    ctx->blocks_processed = 0;
    ctx->domain_tag = domain_tag;
}

void h512_init(h512_ctx *ctx) {
    h512_init_tag(ctx, H512_TAG_STANDARD_512);
}

void h256_init(h512_ctx *ctx) {
    h512_init_tag(ctx, H512_TAG_TRUNCATED_256);
}

void h512_update(h512_ctx *ctx, const void *data, size_t len) {
    const uint8_t *ptr = (const uint8_t *)data;
    ctx->total_bytes += len;

    while (len > 0) {
        size_t to_copy = 64 - ctx->buffer_len;
        if (len < to_copy) to_copy = len;
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
    final_blocks[rem + 1 + k] = ctx->domain_tag;

    for (int i = 0; i < 8; i++) {
        final_blocks[rem + 1 + k + 1 + 7 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    size_t num_blocks = pad_total / 64;
    for (size_t i = 0; i < num_blocks; i++) {
        compress_block_c(ctx->state, final_blocks + i * 64, bit_len);
    }

    if (is_256) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 8; c++) {
                out[r * 8 + c] = ctx->state[r][c] ^ n_bio(ctx->state[r + 4][c]);
            }
        }
    } else {
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

void h512_hash_tag(const void *data, size_t len, uint8_t domain_tag, uint8_t out[64]) {
    h512_ctx ctx;
    h512_init_tag(&ctx, domain_tag);
    h512_update(&ctx, data, len);
    h512_final(&ctx, out);
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

/* ========================================================================= */
/* SECTION 3: AVX2 4-WAY INTER-CHUNK SIMD ENGINE                             */
/* ========================================================================= */
int h512_has_avx2(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("avx2") > 0;
#elif defined(_MSC_VER)
    int cpu_info[4];
    __cpuid(cpu_info, 0);
    if (cpu_info[0] < 7) return 0;
    __cpuidex(cpu_info, 7, 0);
    return (cpu_info[1] & (1 << 5)) != 0;
#else
    return 0;
#endif
}

static inline __m256i xtime_avx2(__m256i x) {
    __m256i shifted = _mm256_and_si256(_mm256_slli_epi64(x, 1), _mm256_set1_epi64x(0xFEFEFEFEFEFEFEFEULL));
    __m256i red = _mm256_blendv_epi8(_mm256_setzero_si256(), _mm256_set1_epi8(0x1B), x);
    return _mm256_xor_si256(shifted, red);
}

static inline __m256i rotl8_avx2(__m256i x, int n) {
    n &= 7;
    if (n == 0) return x;
    uint8_t mask_l = (uint8_t)(0xFF << n);
    uint8_t mask_r = (uint8_t)(0xFF >> (8 - n));
    __m256i ml = _mm256_set1_epi8((char)mask_l);
    __m256i mr = _mm256_set1_epi8((char)mask_r);
    __m256i sl = _mm256_and_si256(_mm256_slli_epi16(x, n), ml);
    __m256i sr = _mm256_and_si256(_mm256_srli_epi16(x, 8 - n), mr);
    return _mm256_or_si256(sl, sr);
}

static inline __m256i rotl_bytes64_avx2(__m256i x, int r) {
    r &= 7;
    if (r == 0) return x;
    return _mm256_or_si256(_mm256_srli_epi64(x, r * 8), _mm256_slli_epi64(x, (8 - r) * 8));
}

static inline __m256i swap32_avx2(__m256i x) {
    return _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
}

static inline __m256i bswap64_avx2(__m256i x) {
    const __m256i mask = _mm256_set_epi8(
        8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7
    );
    return _mm256_shuffle_epi8(x, mask);
}

void h512_compress_4way_avx2(uint8_t S[4][8][8], const uint8_t (*blocks)[64], uint64_t cumulative_bits) {
    h512_state_t S_prev[4];
    for (int k = 0; k < 4; k++) memcpy(S_prev[k].b, S[k], 64);

    uint64_t m_disp_u64[4][8];
    for (int k = 0; k < 4; k++) {
        const uint64_t *M_in = (const uint64_t *)blocks[k];
        for (int r = 0; r < 8; r++) {
            int shift = r & 7;
            uint64_t x = M_in[r];
            m_disp_u64[k][r] = shift ? ((x >> (shift * 8)) | (x << ((8 - shift) * 8))) : x;
        }
    }

    uint8_t t_bytes[8];
    for (int i = 0; i < 8; i++) {
        t_bytes[7 - i] = (uint8_t)(cumulative_bits >> (i * 8));
    }

    __m256i R[2][8];
    for (int r = 0; r < 8; r++) {
        uint64_t w[4];
        for (int k = 0; k < 4; k++) {
            h512_state_t st;
            memcpy(st.b, S[k], 64);
            uint8_t row_bytes[8];
            const uint8_t *md = (const uint8_t *)&m_disp_u64[k][r];
            for (int c = 0; c < 8; c++) {
                row_bytes[c] = st.b[r][c] ^ md[c];
                if (r == c) row_bytes[c] ^= t_bytes[r];
            }
            memcpy(&w[k], row_bytes, 8);
        }
        R[0][r] = _mm256_set_epi64x(w[3], w[2], w[1], w[0]);
    }

    static const int rotations[4][4] = {
        {1, 2, 3, 5},
        {3, 5, 1, 7},
        {5, 1, 7, 3},
        {7, 3, 5, 1}
    };

    for (int rnd = 0; rnd < 16; rnd++) {
        int cur = rnd & 1;
        int next = (rnd + 1) & 1;
        int fam = rnd & 3;
        int alpha = rotations[fam][0];
        int beta  = rotations[fam][1];
        int gamma = rotations[fam][2];
        int delta = rotations[fam][3];

        for (int r = 0; r < 8; r++) {
            __m256i r_cur = R[cur][r];
            __m256i north = R[cur][(r - 1) & 7];
            __m256i south = R[cur][(r + 1) & 7];
            __m256i east  = rotl_bytes64_avx2(r_cur, 1);
            __m256i west  = rotl_bytes64_avx2(r_cur, 7);

            __m256i context = _mm256_xor_si256(
                r_cur,
                _mm256_xor_si256(
                    _mm256_xor_si256(rotl8_avx2(north, alpha), rotl8_avx2(east, beta)),
                    _mm256_xor_si256(rotl8_avx2(south, gamma), rotl8_avx2(west, delta))
                )
            );

            uint8_t ctx_bytes[32], out_bytes[32];
            _mm256_storeu_si256((__m256i*)ctx_bytes, context);
            const uint8_t *rc_row = H512_RC[rnd][r];
            for (int k = 0; k < 4; k++) {
                for (int c = 0; c < 8; c++) {
                    out_bytes[k * 8 + c] = H512_SBOX[ctx_bytes[k * 8 + c]] ^ rc_row[c];
                }
            }
            R[next][r] = _mm256_loadu_si256((const __m256i*)out_bytes);
        }

        {
            __m256i r0 = R[next][0], r1 = R[next][1], r2 = R[next][2], r3 = R[next][3];
            __m256i t_top = _mm256_xor_si256(_mm256_xor_si256(r0, r1), _mm256_xor_si256(r2, r3));
            R[next][0] = _mm256_xor_si256(_mm256_xor_si256(r0, t_top), xtime_avx2(_mm256_xor_si256(r0, r1)));
            R[next][1] = _mm256_xor_si256(_mm256_xor_si256(r1, t_top), xtime_avx2(_mm256_xor_si256(r1, r2)));
            R[next][2] = _mm256_xor_si256(_mm256_xor_si256(r2, t_top), xtime_avx2(_mm256_xor_si256(r2, r3)));
            R[next][3] = _mm256_xor_si256(_mm256_xor_si256(r3, t_top), xtime_avx2(_mm256_xor_si256(r3, r0)));

            __m256i r4 = R[next][4], r5 = R[next][5], r6 = R[next][6], r7 = R[next][7];
            __m256i t_bot = _mm256_xor_si256(_mm256_xor_si256(r4, r5), _mm256_xor_si256(r6, r7));
            R[next][4] = _mm256_xor_si256(_mm256_xor_si256(r4, t_bot), xtime_avx2(_mm256_xor_si256(r4, r5)));
            R[next][5] = _mm256_xor_si256(_mm256_xor_si256(r5, t_bot), xtime_avx2(_mm256_xor_si256(r5, r6)));
            R[next][6] = _mm256_xor_si256(_mm256_xor_si256(r6, t_bot), xtime_avx2(_mm256_xor_si256(r6, r7)));
            R[next][7] = _mm256_xor_si256(_mm256_xor_si256(r7, t_bot), xtime_avx2(_mm256_xor_si256(r7, r4)));
        }

        if (fam == 1 || fam == 3) {
            for (int r = 0; r < 4; r++) {
                __m256i old_r = R[next][r];
                __m256i old_r4 = R[next][r + 4];
                R[next][r] = swap32_avx2(old_r4);
                R[next][r + 4] = swap32_avx2(old_r);
            }
        }

        if (fam == 0) {
            for (int r = 1; r < 8; r++) R[next][r] = rotl_bytes64_avx2(R[next][r], r);
        } else if (fam == 1) {
            uint64_t w[8][4];
            for (int r = 0; r < 8; r++) _mm256_storeu_si256((__m256i*)w[r], R[next][r]);
            for (int k = 0; k < 4; k++) {
                uint8_t mat[8][8];
                for (int r = 0; r < 8; r++) memcpy(mat[r], &w[r][k], 8);
                transpose8x8_inplace(mat);
                for (int r = 0; r < 8; r++) memcpy(&w[r][k], mat[r], 8);
            }
            for (int r = 0; r < 8; r++) R[next][r] = _mm256_loadu_si256((const __m256i*)w[r]);
        } else if (fam == 2) {
            for (int r = 1; r < 8; r++) R[next][r] = rotl_bytes64_avx2(R[next][r], r);
            uint64_t w[8][4];
            for (int r = 0; r < 8; r++) _mm256_storeu_si256((__m256i*)w[r], R[next][r]);
            for (int k = 0; k < 4; k++) {
                uint8_t mat[8][8];
                for (int r = 0; r < 8; r++) memcpy(mat[r], &w[r][k], 8);
                transpose8x8_inplace(mat);
                for (int r = 0; r < 8; r++) memcpy(&w[r][k], mat[r], 8);
            }
            for (int r = 0; r < 8; r++) R[next][r] = _mm256_loadu_si256((const __m256i*)w[r]);
        } else {
            for (int r = 0; r < 8; r++) {
                R[next][r] = bswap64_avx2(rotl_bytes64_avx2(R[next][r], r));
            }
        }
    }

    for (int r = 0; r < 8; r++) {
        uint64_t w[4];
        _mm256_storeu_si256((__m256i*)w, R[0][r]);
        for (int k = 0; k < 4; k++) {
            uint64_t *S_u64 = (uint64_t *)S[k];
            S_u64[r] = w[k] ^ S_prev[k].u64[r] ^ m_disp_u64[k][r];
        }
    }
}

void h512_hash_leaf_chunks_4way_avx2(const uint8_t *const chunks[4], size_t chunk_len, uint8_t out[4][64]) {
    uint8_t S[4][8][8];
    for (int k = 0; k < 4; k++) {
        memcpy(S[k], H512_IV, 64);
    }

    size_t num_blocks = chunk_len / 64;
    for (size_t b = 0; b < num_blocks; b++) {
        uint8_t blocks[4][64];
        for (int k = 0; k < 4; k++) {
            memcpy(blocks[k], chunks[k] + b * 64, 64);
        }
        uint64_t cumulative_bits = (b + 1) * 512;
        h512_compress_4way_avx2(S, (const uint8_t (*)[64])blocks, cumulative_bits);
    }

    size_t rem = chunk_len % 64;
    size_t k_pad = (64 - ((rem + 10) % 64)) % 64;
    uint64_t bit_len = chunk_len * 8;

    uint8_t pad_block[64];
    memset(pad_block, 0, 64);
    pad_block[0] = 0x80;
    pad_block[1 + k_pad] = H512_TAG_TREE_LEAF;
    for (int i = 0; i < 8; i++) {
        pad_block[1 + k_pad + 1 + 7 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    uint8_t pad_blocks[4][64];
    for (int k = 0; k < 4; k++) {
        memcpy(pad_blocks[k], pad_block, 64);
    }
    h512_compress_4way_avx2(S, (const uint8_t (*)[64])pad_blocks, bit_len);

    for (int k = 0; k < 4; k++) {
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 8; c++) {
                out[k][r * 8 + c] = S[k][r][c];
            }
        }
    }
}

/* ========================================================================= */
/* SECTION 4: NATIVE PARALLEL BINARY MERKLE TREE HASHER                      */
/* ========================================================================= */
void h512_tree_hash(const void *data, size_t len, size_t chunk_size, uint8_t out[64]) {
    if (chunk_size == 0) chunk_size = H512_DEFAULT_CHUNK_SIZE;

    if (len <= chunk_size) {
        h512_hash_tag(data, len, H512_TAG_STANDARD_512, out);
        return;
    }

    const uint8_t *ptr = (const uint8_t *)data;
    size_t num_chunks = (len + chunk_size - 1) / chunk_size;

    uint8_t (*nodes)[64] = (uint8_t (*)[64])malloc(num_chunks * 64);
    if (!nodes) {
        fprintf(stderr, "Error: Memory allocation failed in h512_tree_hash.\n");
        return;
    }

    int can_avx2 = (h512_has_avx2() && chunk_size == 1024);
    size_t idx = 0;

    if (can_avx2) {
        while (idx + 4 <= num_chunks && (idx + 4) * chunk_size <= len) {
            const uint8_t *chunks[4];
            for (int k = 0; k < 4; k++) {
                chunks[k] = ptr + (idx + k) * chunk_size;
            }
            uint8_t batch_out[4][64];
            h512_hash_leaf_chunks_4way_avx2(chunks, chunk_size, batch_out);
            for (int k = 0; k < 4; k++) {
                memcpy(nodes[idx + k], batch_out[k], 64);
            }
            idx += 4;
        }
    }

    while (idx < num_chunks) {
        size_t c_offset = idx * chunk_size;
        size_t c_len = (len - c_offset < chunk_size) ? (len - c_offset) : chunk_size;
        h512_hash_tag(ptr + c_offset, c_len, H512_TAG_TREE_LEAF, nodes[idx]);
        idx++;
    }

    size_t current_level_count = num_chunks;
    while (current_level_count > 1) {
        size_t next_level_count = 0;
        for (size_t i = 0; i < current_level_count; i += 2) {
            if (i + 1 < current_level_count) {
                uint8_t pair[128];
                memcpy(pair, nodes[i], 64);
                memcpy(pair + 64, nodes[i + 1], 64);
                h512_hash_tag(pair, 128, H512_TAG_TREE_INTERNAL, nodes[next_level_count]);
                next_level_count++;
            } else {
                if (next_level_count != i) {
                    memcpy(nodes[next_level_count], nodes[i], 64);
                }
                next_level_count++;
            }
        }
        current_level_count = next_level_count;
    }

    h512_hash_tag(nodes[0], 64, H512_TAG_TREE_ROOT, out);
    h512_cleanse(nodes, num_chunks * 64);
    free(nodes);
}

int h512_tree_hash_file(const char *filepath, size_t chunk_size, uint8_t out[64]) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < 0) {
        fclose(fp);
        return -2;
    }

    size_t file_len = (size_t)fsize;
    uint8_t *buffer = (uint8_t *)malloc(file_len ? file_len : 1);
    if (!buffer) {
        fclose(fp);
        return -3;
    }

    if (file_len > 0) {
        size_t read_bytes = fread(buffer, 1, file_len, fp);
        if (read_bytes != file_len) {
            free(buffer);
            fclose(fp);
            return -4;
        }
    }
    fclose(fp);

    h512_tree_hash(buffer, file_len, chunk_size, out);
    free(buffer);
    return 0;
}

/* ========================================================================= */
/* SECTION 5: TORIX-SPONGE MULTI-RATE DUPLEX & XOF                           */
/* ========================================================================= */
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
    torix_sponge_ctx ctx;
    size_t rate = post_quantum ? 16 : 32;
    size_t capacity = 64 - rate;
    uint8_t domain_tag = post_quantum ? 0x06 : 0x05;

    torix_sponge_init(&ctx, rate, capacity, domain_tag);
    torix_sponge_absorb(&ctx, data, len);
    torix_sponge_squeeze(&ctx, out, out_len);
    h512_cleanse(&ctx, sizeof(ctx));
}

/* ========================================================================= */
/* SECTION 6: TORIX-AEAD AUTHENTICATED ENCRYPTION                            */
/* ========================================================================= */
void torix_aead_encrypt(const uint8_t key[32],
                        const uint8_t nonce[16],
                        const uint8_t *plaintext,
                        size_t pt_len,
                        const uint8_t *associated_data,
                        size_t ad_len,
                        uint8_t *ciphertext,
                        uint8_t tag[32]) {
    torix_sponge_ctx ctx;
    torix_sponge_init(&ctx, 32, 32, 0x10);

    /* Absorb Key || Nonce (48 bytes) */
    uint8_t kn_buf[48];
    memcpy(kn_buf, key, 32);
    memcpy(kn_buf + 32, nonce, 16);
    torix_sponge_absorb(&ctx, kn_buf, 48);
    h512_cleanse(kn_buf, 48);

    /* Absorb Associated Data (if present) */
    if (ad_len > 0 && associated_data) {
        torix_sponge_absorb(&ctx, associated_data, ad_len);
        ((uint8_t *)ctx.state)[63] ^= 0x02;
        h512_permute_p16(ctx.state);
    }

    /* Stream encryption of plaintext */
    size_t offset = 0;
    while (offset < pt_len) {
        size_t block_len = (pt_len - offset < 32) ? (pt_len - offset) : 32;
        uint8_t key_stream[32];
        torix_sponge_squeeze(&ctx, key_stream, 32);

        for (size_t i = 0; i < block_len; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ key_stream[i];
        }

        uint8_t *raw_state = (uint8_t *)ctx.state;
        for (size_t i = 0; i < block_len; i++) {
            raw_state[i] ^= ciphertext[offset + i];
        }
        h512_permute_p8(ctx.state);

        offset += block_len;
        h512_cleanse(key_stream, 32);
    }

    /* Finalize and generate authentication tag */
    ((uint8_t *)ctx.state)[63] ^= 0x03;
    h512_permute_p16(ctx.state);
    torix_sponge_squeeze(&ctx, tag, 32);

    h512_cleanse(&ctx, sizeof(ctx));
}

int torix_aead_decrypt(const uint8_t key[32],
                       const uint8_t nonce[16],
                       const uint8_t *ciphertext,
                       size_t ct_len,
                       const uint8_t tag[32],
                       const uint8_t *associated_data,
                       size_t ad_len,
                       uint8_t *plaintext) {
    torix_sponge_ctx ctx;
    torix_sponge_init(&ctx, 32, 32, 0x10);

    /* Absorb Key || Nonce (48 bytes) */
    uint8_t kn_buf[48];
    memcpy(kn_buf, key, 32);
    memcpy(kn_buf + 32, nonce, 16);
    torix_sponge_absorb(&ctx, kn_buf, 48);
    h512_cleanse(kn_buf, 48);

    /* Absorb Associated Data */
    if (ad_len > 0 && associated_data) {
        torix_sponge_absorb(&ctx, associated_data, ad_len);
        ((uint8_t *)ctx.state)[63] ^= 0x02;
        h512_permute_p16(ctx.state);
    }

    /* Stream decryption of ciphertext */
    size_t offset = 0;
    while (offset < ct_len) {
        size_t block_len = (ct_len - offset < 32) ? (ct_len - offset) : 32;
        uint8_t key_stream[32];
        torix_sponge_squeeze(&ctx, key_stream, 32);

        for (size_t i = 0; i < block_len; i++) {
            plaintext[offset + i] = ciphertext[offset + i] ^ key_stream[i];
        }

        uint8_t *raw_state = (uint8_t *)ctx.state;
        for (size_t i = 0; i < block_len; i++) {
            raw_state[i] ^= ciphertext[offset + i];
        }
        h512_permute_p8(ctx.state);

        offset += block_len;
        h512_cleanse(key_stream, 32);
    }

    /* Generate expected authentication tag */
    uint8_t expected_tag[32];
    ((uint8_t *)ctx.state)[63] ^= 0x03;
    h512_permute_p16(ctx.state);
    torix_sponge_squeeze(&ctx, expected_tag, 32);

    /* Constant-time tag verification */
    int valid = h512_verify_mac(tag, expected_tag, 32);

    /* If validation fails, wipe decrypted plaintext to prevent plaintext leakage */
    if (!valid) {
        h512_cleanse(plaintext, ct_len);
    }

    h512_cleanse(expected_tag, 32);
    h512_cleanse(&ctx, sizeof(ctx));
    return valid;
}

/* ========================================================================= */
/* SECTION 7: NIST/FIPS-STYLE POWER-ON SELF-TEST (POST)                      */
/* ========================================================================= */

/* Golden Known Answer Test (KAT) Vectors */
static const uint8_t KAT_H512_ABC[64] = {
    0x97, 0xba, 0xae, 0xc0, 0xf0, 0x4a, 0x1c, 0xf0,
    0x9d, 0x88, 0x84, 0x8a, 0x4b, 0xf3, 0x26, 0x51,
    0xd3, 0x39, 0x89, 0x2f, 0x56, 0x60, 0x09, 0x6e,
    0x5d, 0xd6, 0x0d, 0xef, 0xde, 0x26, 0xd0, 0xf1,
    0xa9, 0x4a, 0xb0, 0x8d, 0x34, 0xac, 0x56, 0x05,
    0x84, 0x37, 0x62, 0xfd, 0xb2, 0x49, 0xc1, 0x0e,
    0xf2, 0xac, 0xf0, 0x2c, 0x0a, 0x59, 0x52, 0x6c,
    0x94, 0xd9, 0xa7, 0x18, 0xfc, 0x8b, 0xe0, 0x79
};

static const uint8_t KAT_H256_ABC[32] = {
    0x34, 0x0f, 0xd4, 0xb0, 0xc9, 0x28, 0xc1, 0xe5,
    0x2e, 0x40, 0x76, 0xe4, 0xef, 0x4d, 0xad, 0x07,
    0x21, 0x59, 0x7a, 0x41, 0x80, 0xd8, 0x00, 0x04,
    0xcb, 0x84, 0xf4, 0x32, 0x6d, 0x64, 0x01, 0x53
};

static const uint8_t KAT_H512_EMPTY[64] = {
    0xc4, 0x3c, 0xc2, 0x67, 0xc5, 0xe9, 0x8b, 0x5c,
    0x8c, 0x9b, 0x54, 0x38, 0x14, 0xe1, 0xb3, 0xc5,
    0xce, 0xe7, 0x67, 0xcf, 0x1f, 0x21, 0x4d, 0x89,
    0xcf, 0x1d, 0x47, 0x09, 0x0a, 0xbf, 0x7a, 0x73,
    0xec, 0x2d, 0xe9, 0x5b, 0xf8, 0x3a, 0x19, 0x07,
    0xba, 0x0b, 0x9f, 0xde, 0xa0, 0x14, 0xdb, 0x70,
    0xf0, 0x09, 0x2e, 0xf6, 0xb8, 0x1a, 0x71, 0xd1,
    0x4f, 0x45, 0xfc, 0x7a, 0x14, 0x39, 0x1f, 0x92
};

static const uint8_t KAT_TREE_4096[64] = {
    0x54, 0xe3, 0xc3, 0xe5, 0x49, 0x72, 0xd6, 0xcc,
    0x30, 0x7a, 0xdb, 0x6a, 0xd3, 0xfe, 0x2f, 0x9d,
    0x30, 0x4b, 0x15, 0x5d, 0x4a, 0xca, 0xba, 0x33,
    0x84, 0x16, 0x06, 0xb6, 0x1a, 0x78, 0xc2, 0xfd,
    0x46, 0x18, 0xcf, 0x32, 0x43, 0xb6, 0x00, 0x10,
    0x31, 0xed, 0xfb, 0xad, 0xb1, 0xf8, 0x7b, 0x88,
    0xaf, 0x7e, 0xed, 0xc6, 0xce, 0x9e, 0x5c, 0x00,
    0x09, 0x46, 0x02, 0x4e, 0x19, 0x15, 0x3a, 0xb9
};

int h512_self_test(void) {
    uint8_t out512[64];
    uint8_t out256[32];
    uint8_t out_tree[64];
    uint8_t payload[4096];
    int status = H512_SELF_TEST_PASS;

    /* 1. TORIX-512 Standard KAT ("abc") */
    h512_hash((const uint8_t *)"abc", 3, out512);
    if (!h512_verify_mac(out512, KAT_H512_ABC, 64)) {
        status = H512_SELF_TEST_FAIL;
    }

    /* 2. TORIX-256 Standard KAT ("abc") */
    h256_hash((const uint8_t *)"abc", 3, out256);
    if (!h512_verify_mac(out256, KAT_H256_ABC, 32)) {
        status = H512_SELF_TEST_FAIL;
    }

    /* 3. TORIX-512 Empty Vector KAT ("") */
    h512_hash((const uint8_t *)"", 0, out512);
    if (!h512_verify_mac(out512, KAT_H512_EMPTY, 64)) {
        status = H512_SELF_TEST_FAIL;
    }

    /* 4. Parallel Tree Hasher KAT on 4096-byte deterministic vector */
    for (size_t i = 0; i < 4096; i++) {
        payload[i] = (uint8_t)((i * 47 + 19) & 0xFF);
    }
    h512_tree_hash(payload, 4096, 1024, out_tree);
    if (!h512_verify_mac(out_tree, KAT_TREE_4096, 64)) {
        status = H512_SELF_TEST_FAIL;
    }

    /* 5. Constant-time MAC verify fault injection sanity check:
          Ensure h512_verify_mac rejects corrupted buffer */
    out512[0] ^= 0x55;
    if (h512_verify_mac(out512, KAT_H512_EMPTY, 64)) {
        status = H512_SELF_TEST_FAIL;
    }

    /* Strict cryptographic scrubbing */
    h512_cleanse(out512, sizeof(out512));
    h512_cleanse(out256, sizeof(out256));
    h512_cleanse(out_tree, sizeof(out_tree));
    h512_cleanse(payload, sizeof(payload));

    return status;
}

/* ========================================================================= */
/* SECTION 8: KEYED PASSWORD HASHING (SALT + PEPPER KDF)                     */
/* ========================================================================= */
void torix_hash_password(const char *password,
                         const uint8_t salt[16],
                         const char *pepper,
                         int iterations,
                         uint8_t out[64]) {
    if (!password || !salt || iterations <= 0 || !out) return;

    size_t pw_len = strlen(password);
    size_t pep_len = (pepper && pepper[0] != '\0') ? strlen(pepper) : 0;

    /* Initial payload: salt (16) + "::" (2) + [pepper + "::"] + password (pw_len) */
    size_t init_len = 16 + 2 + (pep_len ? (pep_len + 2) : 0) + pw_len;
    uint8_t *init_buf = (uint8_t *)malloc(init_len);
    if (!init_buf) return;

    memcpy(init_buf, salt, 16);
    memcpy(init_buf + 16, "::", 2);
    size_t offset = 18;
    if (pep_len > 0) {
        memcpy(init_buf + offset, pepper, pep_len);
        offset += pep_len;
        memcpy(init_buf + offset, "::", 2);
        offset += 2;
    }
    memcpy(init_buf + offset, password, pw_len);

    uint8_t current[64];
    h512_hash(init_buf, init_len, current);
    h512_cleanse(init_buf, init_len);
    free(init_buf);

    /* Round payload: current (64) + [pepper] + password (pw_len) */
    size_t round_extra_len = pep_len + pw_len;
    size_t round_len = 64 + round_extra_len;
    uint8_t *round_buf = (uint8_t *)malloc(round_len);
    if (!round_buf) {
        h512_cleanse(current, 64);
        return;
    }

    if (pep_len > 0) {
        memcpy(round_buf + 64, pepper, pep_len);
    }
    memcpy(round_buf + 64 + pep_len, password, pw_len);

    for (int i = 1; i < iterations; i++) {
        memcpy(round_buf, current, 64);
        h512_hash(round_buf, round_len, current);
    }

    h512_cleanse(round_buf, round_len);
    free(round_buf);

    memcpy(out, current, 64);
    h512_cleanse(current, 64);
}

int torix_verify_password(const char *password,
                          const uint8_t salt[16],
                          const char *pepper,
                          int iterations,
                          const uint8_t expected_hash[64]) {
    if (!password || !salt || !expected_hash || iterations <= 0) return 0;

    uint8_t computed[64];
    torix_hash_password(password, salt, pepper, iterations, computed);
    int match = h512_verify_mac(computed, expected_hash, 64);
    h512_cleanse(computed, 64);
    return match;
}

#if defined(__GNUC__) || defined(__clang__)
    #pragma GCC pop_options
#endif
