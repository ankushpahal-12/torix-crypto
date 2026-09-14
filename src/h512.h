/**
 * Project H-512 / TORIX-512 Unified Cryptographic Engine Header
 * =============================================================
 * Zero-allocation, high-performance cryptographic primitive suite:
 * - TORIX-512 / TORIX-256 HAIFA Cryptographic Hash Functions
 * - Inter-Chunk 4-Way AVX2 SIMD Vectorization (3+ GB/s Leaf Engine)
 * - Parallel Binary Merkle Tree Hasher (O(log N) Verifiable Streaming)
 * - Multi-Rate Duplex Cryptographic Sponge & XOF Engine
 * - Single-Pass Authenticated Encryption with Associated Data (AEAD)
 * - Constant-time Side-Channel Hardening & Volatile State Cleansing
 */

#ifndef H512_H
#define H512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* 1. DOMAIN SEPARATION CONSTANTS (HAIFA Tags 0x00..0x05)                    */
/* ========================================================================= */
#define H512_TAG_STANDARD_512  0x00
#define H512_TAG_TRUNCATED_256 0x01
#define H512_TAG_TREE_LEAF      0x02
#define H512_TAG_TREE_INTERNAL  0x03
#define H512_TAG_TREE_ROOT      0x04
#define H512_TAG_XOF_STREAM     0x05

#define H512_DEFAULT_CHUNK_SIZE 1024

/* ========================================================================= */
/* 2. CORE HASH STATE & STREAMING API                                        */
/* ========================================================================= */
typedef struct {
    uint8_t state[8][8];
    uint8_t buffer[64];
    size_t  buffer_len;
    uint64_t total_bytes;
    uint64_t blocks_processed;
    uint8_t domain_tag;
} h512_ctx;

void h512_init(h512_ctx *ctx);
void h256_init(h512_ctx *ctx);
void h512_init_tag(h512_ctx *ctx, uint8_t domain_tag);
void h512_update(h512_ctx *ctx, const void *data, size_t len);
void h512_final(h512_ctx *ctx, uint8_t out[64]);
void h256_final(h512_ctx *ctx, uint8_t out[32]);

/* One-shot API */
void h512_hash(const void *data, size_t len, uint8_t out[64]);
void h256_hash(const void *data, size_t len, uint8_t out[32]);
void h512_hash_tag(const void *data, size_t len, uint8_t domain_tag, uint8_t out[64]);

/* Hex Formatting Helper */
void h512_to_hex(const uint8_t *bytes, size_t len, char *hex_out);

/* Side-Channel Defense & State Cleansing */
int  h512_verify_mac(const uint8_t *a, const uint8_t *b, size_t len);
void h512_cleanse(void *v, size_t n);

/* FIPS 140-3 Power-On Self-Test (POST) */
#define H512_SELF_TEST_PASS 1
#define H512_SELF_TEST_FAIL 0
int  h512_self_test(void);

/* Core Permutation Primitives */
void h512_permute_p16(uint8_t S[8][8]);
void h512_permute_p8(uint8_t S[8][8]);

/* ========================================================================= */
/* 3. AVX2 INTER-CHUNK SIMD VECTORIZATION                                    */
/* ========================================================================= */
int  h512_has_avx2(void);
void h512_compress_4way_avx2(uint8_t S[4][8][8], const uint8_t (*blocks)[64], uint64_t cumulative_bits);
void h512_hash_leaf_chunks_4way_avx2(const uint8_t *const chunks[4], size_t chunk_len, uint8_t out[4][64]);

/* ========================================================================= */
/* 4. NATIVE PARALLEL BINARY MERKLE TREE HASHER                              */
/* ========================================================================= */
void h512_tree_hash(const void *data, size_t len, size_t chunk_size, uint8_t out[64]);
int  h512_tree_hash_file(const char *filepath, size_t chunk_size, uint8_t out[64]);

/* ========================================================================= */
/* 5. TORIX-SPONGE MULTI-RATE DUPLEX & XOF                                   */
/* ========================================================================= */
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
void torix_xof(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, int post_quantum);

/* ========================================================================= */
/* 6. TORIX-AEAD AUTHENTICATED ENCRYPTION                                    */
/* ========================================================================= */
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

/* ========================================================================= */
/* 7. NIST/FIPS-STYLE POWER-ON SELF-TEST (POST)                              */
/* ========================================================================= */
#define H512_SELF_TEST_PASS 1
#define H512_SELF_TEST_FAIL 0

/**
 * @brief Power-On Self-Test (POST) conforming to NIST CAVP / FIPS 140-3 guidelines.
 *
 * Verifies:
 * 1. TORIX-512 standard KAT ("abc")
 * 2. TORIX-256 standard KAT ("abc")
 * 3. TORIX-512 empty input KAT ("")
 * 4. Parallel Binary Tree Hasher KAT (4096-byte deterministic vector)
 * 5. Constant-time MAC verify rejection behavior (fault injection)
 *
 * All scratch buffers are strictly wiped using h512_cleanse.
 *
 * @return H512_SELF_TEST_PASS (1) on complete integrity, H512_SELF_TEST_FAIL (0) on any anomaly.
 */
int h512_self_test(void);

/* ========================================================================= */
/* 8. KEYED PASSWORD HASHING (SALT + PEPPER KDF)                             */
/* ========================================================================= */
/**
 * @brief Derives a 64-byte key-stretched password digest with salt and optional pepper.
 *
 * @param password Null-terminated password string.
 * @param salt 16-byte cryptographically secure random salt.
 * @param pepper Optional null-terminated server-side secret key (pass NULL or "" for un-peppered).
 * @param iterations Number of stretching iterations (recommended: 4096 or higher).
 * @param out Output buffer receiving the 64-byte digest.
 */
void torix_hash_password(const char *password,
                         const uint8_t salt[16],
                         const char *pepper,
                         int iterations,
                         uint8_t out[64]);

/**
 * @brief Verifies a password against an expected 64-byte digest in constant time.
 *
 * @param password Null-terminated password string.
 * @param salt 16-byte salt from the database.
 * @param pepper Optional server-side secret key.
 * @param iterations Number of stretching iterations.
 * @param expected_hash Expected 64-byte hash from the database.
 * @return 1 if password matches, 0 on mismatch.
 */
int torix_verify_password(const char *password,
                          const uint8_t salt[16],
                          const char *pepper,
                          int iterations,
                          const uint8_t expected_hash[64]);

#ifdef __cplusplus
}
#endif

#endif /* H512_H */
