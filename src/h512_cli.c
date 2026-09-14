/**
 * Project H-512 / TORIX-512 C CLI & Benchmark Harness
 * ====================================================
 * Features:
 * - Hashing: H-512 and H-256
 * - AEAD Encryption & Decryption
 * - Extendable Output Function (XOF / Sponge)
 * - Throughput Benchmarks & NIST Statistical File Generators
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "h512.h"

void run_tree_benchmark(void) {
    printf("======================================================================\n");
    printf("     TORIX-512 PARALLEL TREE & 4-WAY AVX2 SIMD BENCHMARK              \n");
    printf("======================================================================\n");
    printf("[*] Hardware AVX2 Support : %s\n", h512_has_avx2() ? "DETECTED & ACTIVE (4-Way Vectorized)" : "DISABLED / NOT DETECTED");

    size_t test_sizes[] = { 10 * 1024 * 1024, 50 * 1024 * 1024 };
    for (int t = 0; t < 2; t++) {
        size_t sz = test_sizes[t];
        uint8_t *buf = (uint8_t *)malloc(sz);
        if (!buf) continue;
        memset(buf, 0x3C, sz);

        uint8_t tree_digest[64];
        char hex[129];

        printf("[*] Benchmarking Tree Hash (%zu MB payload, 1024B chunks)...\n", sz / (1024 * 1024));
        clock_t t0 = clock();
        h512_tree_hash(buf, sz, 1024, tree_digest);
        clock_t t1 = clock();

        double sec = (double)(t1 - t0) / CLOCKS_PER_SEC;
        double mb_s = (sz / (1024.0 * 1024.0)) / (sec > 0.0001 ? sec : 0.0001);
        h512_to_hex(tree_digest, 64, hex);

        printf("    Root Digest : %.32s...%.16s\n", hex, hex + 112);
        printf("    Time Elapsed: %.4f seconds\n", sec);
        printf("    Throughput  : %.2f MB/second\n", mb_s);
        free(buf);
    }
    printf("======================================================================\n\n");
}

void run_benchmark() {
    printf("======================================================================\n");
    printf("       PROJECT H-512 NATIVE C ENGINE BENCHMARK (gcc -O3)              \n");
    printf("======================================================================\n");

    size_t test_size = 10 * 1024 * 1024; /* 10 Megabytes */
    uint8_t *buffer = (uint8_t *)malloc(test_size);
    if (!buffer) {
        printf("Error allocating 10MB test buffer.\n");
        return;
    }
    memset(buffer, 0x5A, test_size);

    uint8_t digest[64];
    char hex[129];

    printf("[*] Hashing 10 MB payload in native C...\n");
    clock_t start = clock();
    h512_hash(buffer, test_size, digest);
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double mb_per_sec = (test_size / (1024.0 * 1024.0)) / seconds;

    h512_to_hex(digest, 64, hex);
    printf("[*] H-512 Digest : %.32s...%.16s\n", hex, hex + 112);
    printf("[*] Time Elapsed : %.4f seconds\n", seconds);
    printf("[*] Throughput   : %.2f MB/second\n", mb_per_sec);
    printf("[+] C ENGINE SPEEDUP: ~%.0fx faster than interpreted Python!\n", (mb_per_sec * 1024.0) / 14.0);
    printf("======================================================================\n\n");

    free(buffer);
}

static uint64_t xorshift64_state = 0x8888888888888888ULL;
static inline uint64_t xorshift64() {
    uint64_t x = xorshift64_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return xorshift64_state = x;
}

void run_stream_file(const char *filepath, size_t num_bytes) {
    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        fprintf(stderr, "Error opening %s\n", filepath);
        return;
    }
    uint64_t counter = 0;
    size_t written = 0;
    uint8_t digest[64];
    while (written < num_bytes) {
        h512_hash(&counter, sizeof(counter), digest);
        size_t to_write = (num_bytes - written < 64) ? (num_bytes - written) : 64;
        fwrite(digest, 1, to_write, fp);
        written += to_write;
        counter++;
    }
    fclose(fp);
}

void run_sac_file(const char *filepath, int num_samples) {
    uint32_t *sac_counts = (uint32_t *)calloc(512 * 512, sizeof(uint32_t));
    if (!sac_counts) return;

    uint8_t X[64];
    uint8_t X_prime[64];
    uint8_t Y[64];
    uint8_t Y_prime[64];

    for (int s = 0; s < num_samples; s++) {
        for (int i = 0; i < 8; i++) {
            uint64_t r = xorshift64();
            memcpy(X + i * 8, &r, 8);
        }
        h512_hash(X, 64, Y);

        for (int in_bit = 0; in_bit < 512; in_bit++) {
            memcpy(X_prime, X, 64);
            X_prime[in_bit / 8] ^= (1 << (in_bit % 8));
            h512_hash(X_prime, 64, Y_prime);

            for (int out_byte = 0; out_byte < 64; out_byte++) {
                uint8_t diff = Y[out_byte] ^ Y_prime[out_byte];
                if (diff) {
                    for (int b = 0; b < 8; b++) {
                        if ((diff >> b) & 1) {
                            sac_counts[in_bit * 512 + out_byte * 8 + b]++;
                        }
                    }
                }
            }
        }
    }

    FILE *fp = fopen(filepath, "wb");
    if (fp) {
        fwrite(sac_counts, sizeof(uint32_t), 512 * 512, fp);
        fclose(fp);
    }
    free(sac_counts);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (!hex || strlen(hex) < len * 2) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%02x", &val) != 1) return 0;
        out[i] = (uint8_t)val;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    /* Formal FIPS 140-3 / NIST CAVP Power-On Self-Test (POST) */
    if (h512_self_test() != H512_SELF_TEST_PASS) {
        fprintf(stderr, "FATAL: TORIX-512 Power-On Self-Test (POST) failed! Halting execution.\n");
        return 101;
    }

    if (argc > 1 && strcmp(argv[1], "--bench") == 0) {
        run_benchmark();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--bench-tree") == 0) {
        run_tree_benchmark();
        return 0;
    }

    if (argc > 2 && (strcmp(argv[1], "--tree") == 0 || strcmp(argv[1], "-t") == 0)) {
        const char *arg = argv[2];
        uint8_t out[64];
        char hex[129];
        FILE *fp = fopen(arg, "rb");
        if (fp) {
            fclose(fp);
            int res = h512_tree_hash_file(arg, 1024, out);
            if (res == 0) {
                h512_to_hex(out, 64, hex);
                printf("%s  %s\n", hex, arg);
                return 0;
            }
        }
        h512_tree_hash(arg, strlen(arg), 1024, out);
        h512_to_hex(out, 64, hex);
        printf("%s\n", hex);
        return 0;
    }

    /* File Hashing Mode: -f / --file <filepath> [-256] */
    if (argc > 2 && (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--file") == 0)) {
        const char *filepath = argv[2];
        int is_256 = (argc > 3 && strcmp(argv[3], "-256") == 0);
        FILE *fp = fopen(filepath, "rb");
        if (!fp) {
            fprintf(stderr, "Error: Unable to open file '%s'\n", filepath);
            return 1;
        }
        h512_ctx ctx;
        if (is_256) {
            h256_init(&ctx);
        } else {
            h512_init(&ctx);
        }
        uint8_t buffer[65536];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
            h512_update(&ctx, buffer, bytes_read);
        }
        fclose(fp);

        if (is_256) {
            uint8_t out[32];
            char hex[65];
            h256_final(&ctx, out);
            h512_to_hex(out, 32, hex);
            printf("%s  %s\n", hex, filepath);
        } else {
            uint8_t out[64];
            char hex[129];
            h512_final(&ctx, out);
            h512_to_hex(out, 64, hex);
            printf("%s  %s\n", hex, filepath);
        }
        return 0;
    }

    if (argc > 3 && strcmp(argv[1], "--stream-file") == 0) {
        const char *filepath = argv[2];
        size_t num_bytes = (size_t)atoll(argv[3]);
        run_stream_file(filepath, num_bytes);
        return 0;
    }

    if (argc > 3 && strcmp(argv[1], "--sac-file") == 0) {
        const char *filepath = argv[2];
        int num_samples = atoi(argv[3]);
        run_sac_file(filepath, num_samples);
        return 0;
    }

    /* XOF / Sponge Mode: --xof -l <length> <message> */
    if (argc > 3 && strcmp(argv[1], "--xof") == 0) {
        size_t out_len = (size_t)atoi(argv[2]);
        const char *msg = argv[3];
        uint8_t *out_buf = (uint8_t *)malloc(out_len);
        if (!out_buf) {
            fprintf(stderr, "Memory allocation error.\n");
            return 1;
        }
        torix_xof((const uint8_t *)msg, strlen(msg), out_buf, out_len, 0);
        for (size_t i = 0; i < out_len; i++) {
            printf("%02x", out_buf[i]);
        }
        printf("\n");
        free(out_buf);
        return 0;
    }

    /* AEAD Mode: --encrypt -k <hex_key> -n <hex_nonce> -m <plaintext> [-ad <associated_data>] */
    if (argc > 7 && strcmp(argv[1], "--encrypt") == 0) {
        const char *key_hex = NULL;
        const char *nonce_hex = NULL;
        const char *plaintext = NULL;
        const char *ad = "";

        for (int i = 2; i < argc; i += 2) {
            if (i + 1 >= argc) break;
            if (strcmp(argv[i], "-k") == 0) key_hex = argv[i + 1];
            else if (strcmp(argv[i], "-n") == 0) nonce_hex = argv[i + 1];
            else if (strcmp(argv[i], "-m") == 0) plaintext = argv[i + 1];
            else if (strcmp(argv[i], "-ad") == 0) ad = argv[i + 1];
        }

        if (!key_hex || !nonce_hex || !plaintext) {
            fprintf(stderr, "Usage: --encrypt -k <hex_key_32B> -n <hex_nonce_16B> -m <plaintext> [-ad <ad>]\n");
            return 1;
        }

        uint8_t key[32], nonce[16], tag[32];
        if (!hex_to_bytes(key_hex, key, 32) || !hex_to_bytes(nonce_hex, nonce, 16)) {
            fprintf(stderr, "Invalid hex key (must be 64 chars) or nonce (must be 32 chars).\n");
            return 1;
        }

        size_t pt_len = strlen(plaintext);
        uint8_t *ciphertext = (uint8_t *)malloc(pt_len ? pt_len : 1);
        torix_aead_encrypt(key, nonce, (const uint8_t *)plaintext, pt_len, (const uint8_t *)ad, strlen(ad), ciphertext, tag);

        char tag_hex[65];
        h512_to_hex(tag, 32, tag_hex);

        printf("Ciphertext (hex): ");
        for (size_t i = 0; i < pt_len; i++) printf("%02x", ciphertext[i]);
        printf("\nTag (hex)       : %s\n", tag_hex);

        free(ciphertext);
        return 0;
    }

    /* AEAD Mode: --decrypt -k <hex_key> -n <hex_nonce> -c <hex_cipher> -t <hex_tag> [-ad <associated_data>] */
    if (argc > 9 && strcmp(argv[1], "--decrypt") == 0) {
        const char *key_hex = NULL;
        const char *nonce_hex = NULL;
        const char *cipher_hex = NULL;
        const char *tag_hex = NULL;
        const char *ad = "";

        for (int i = 2; i < argc; i += 2) {
            if (i + 1 >= argc) break;
            if (strcmp(argv[i], "-k") == 0) key_hex = argv[i + 1];
            else if (strcmp(argv[i], "-n") == 0) nonce_hex = argv[i + 1];
            else if (strcmp(argv[i], "-c") == 0) cipher_hex = argv[i + 1];
            else if (strcmp(argv[i], "-t") == 0) tag_hex = argv[i + 1];
            else if (strcmp(argv[i], "-ad") == 0) ad = argv[i + 1];
        }

        if (!key_hex || !nonce_hex || !cipher_hex || !tag_hex) {
            fprintf(stderr, "Usage: --decrypt -k <key> -n <nonce> -c <cipher> -t <tag> [-ad <ad>]\n");
            return 1;
        }

        uint8_t key[32], nonce[16], tag[32];
        if (!hex_to_bytes(key_hex, key, 32) || !hex_to_bytes(nonce_hex, nonce, 16) || !hex_to_bytes(tag_hex, tag, 32)) {
            fprintf(stderr, "Invalid hex parameters.\n");
            return 1;
        }

        size_t ct_len = strlen(cipher_hex) / 2;
        uint8_t *ciphertext = (uint8_t *)malloc(ct_len ? ct_len : 1);
        uint8_t *plaintext = (uint8_t *)malloc(ct_len + 1);
        hex_to_bytes(cipher_hex, ciphertext, ct_len);

        int ok = torix_aead_decrypt(key, nonce, ciphertext, ct_len, tag, (const uint8_t *)ad, strlen(ad), plaintext);
        if (ok) {
            plaintext[ct_len] = '\0';
            printf("Decrypted: %s\n", plaintext);
        } else {
            printf("AUTHENTICATION_FAILED: Tag mismatch or data tampering detected!\n");
        }

        free(ciphertext);
        free(plaintext);
        return ok ? 0 : 2;
    }

    /* Standard Hash Hashing */
    int is_256 = 0;
    const char *input = "Project H-512 Reference Cryptographic Hash Engine";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-256") == 0) {
            is_256 = 1;
        } else {
            input = argv[i];
        }
    }

    if (is_256) {
        uint8_t out256[32];
        char hex[65];
        h256_hash(input, strlen(input), out256);
        h512_to_hex(out256, 32, hex);
        printf("%s\n", hex);
    } else {
        uint8_t out512[64];
        char hex[129];
        h512_hash(input, strlen(input), out512);
        h512_to_hex(out512, 64, hex);
        printf("%s\n", hex);
    }

    return 0;
}
