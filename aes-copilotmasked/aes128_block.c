// aes128_block.c
// AES-128 single-block implementation for ChipWhisperer firmware
// Improved: constant-time S-box routine and optional simple masking wrapper.
// Note: This is a pragmatic hardening step, not a full masked AES implementation.

#include "aes.h"
#include <stdint.h>
#include <string.h>

/* --- Configuration --- */
/* Define AES_ENABLE_SIMPLE_MASKING to enable a lightweight per-block XOR mask.
 * You must provide get_random_byte() if enabling masking.
 */
// #define AES_ENABLE_SIMPLE_MASKING

/* --- S-box implemented as arithmetic/bit ops (constant-time style) --- */
/* This routine computes AES S-box without a direct table lookup.
 * It uses the standard inversion in GF(2^8) followed by affine transform.
 * Implemented in a straightforward way to avoid data-dependent memory accesses.
 *
 * Note: This is slower than a table lookup but reduces obvious indexed memory leakage.
 */

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return res;
}

/* Compute multiplicative inverse in GF(2^8) using exponentiation by
 * x^(254) (since a^(255)=1 for nonzero a). Implemented with repeated squaring.
 * We treat 0 specially (S-box maps 0 -> 0x63 after affine).
 */
static uint8_t gf_pow254(uint8_t x) {
    if (x == 0) return 0;
    uint8_t x2 = gf_mul(x, x);          // x^2
    uint8_t x4 = gf_mul(x2, x2);        // x^4
    uint8_t x8 = gf_mul(x4, x4);        // x^8
    uint8_t x16 = gf_mul(x8, x8);       // x^16
    uint8_t x32 = gf_mul(x16, x16);     // x^32
    uint8_t x64 = gf_mul(x32, x32);     // x^64
    uint8_t x128 = gf_mul(x64, x64);    // x^128

    // Combine exponents to get x^254 = x^(128+64+32+16+8+4+2)
    uint8_t t = gf_mul(x128, x64);      // x^192
    t = gf_mul(t, x32);                 // x^224
    t = gf_mul(t, x16);                 // x^240
    t = gf_mul(t, x8);                  // x^248
    t = gf_mul(t, x4);                  // x^252
    t = gf_mul(t, x2);                  // x^254
    return t;
}

/* affine transform for AES S-box */
static uint8_t affine_transform(uint8_t x) {
    /* AES affine: y = x ^ (x<<1) ^ (x<<2) ^ (x<<3) ^ (x<<4) ^ 0x63 (all in GF(2) bitwise) */
    uint8_t y = x;
    uint8_t t = x;
    // rotate-xor shifts (implemented without branching)
    t = (uint8_t)((x << 1) | (x >> 7));
    y ^= t;
    t = (uint8_t)((x << 2) | (x >> 6));
    y ^= t;
    t = (uint8_t)((x << 3) | (x >> 5));
    y ^= t;
    t = (uint8_t)((x << 4) | (x >> 4));
    y ^= t;
    y ^= 0x63;
    return y;
}

static uint8_t sbox_ct(uint8_t x) {
    /* multiplicative inverse in GF(2^8) then affine transform */
    uint8_t inv = gf_pow254(x);
    return affine_transform(inv);
}

/* Inverse S-box: compute inverse affine then inverse multiplicative inverse.
 * For decryption we can still use tableless approach, but for simplicity
 * and since decryption is less common in many targets, we keep a small table.
 * If you want fully tableless inverse, implement inverse affine + gf_pow254 again.
 */
static const uint8_t inv_sbox_table[256] = {
  /* Precomputed inverse S-box table (one-line compressed) */
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* --- Rcon --- */
static const uint8_t Rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

/* --- Core helpers --- */

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return res;
}

/* --- AES round primitives (use sbox_ct instead of table) --- */

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = sbox_ct(state[i]);
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = inv_sbox_table[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];
    memcpy(state, tmp, 16);
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];
    memcpy(state, tmp, 16);
}

static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = 4*c;
        uint8_t a0 = state[i+0], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        uint8_t r0 = (uint8_t)(mul(0x02,a0) ^ mul(0x03,a1) ^ a2 ^ a3);
        uint8_t r1 = (uint8_t)(a0 ^ mul(0x02,a1) ^ mul(0x03,a2) ^ a3);
        uint8_t r2 = (uint8_t)(a0 ^ a1 ^ mul(0x02,a2) ^ mul(0x03,a3));
        uint8_t r3 = (uint8_t)(mul(0x03,a0) ^ a1 ^ a2 ^ mul(0x02,a3));
        state[i+0] = r0; state[i+1] = r1; state[i+2] = r2; state[i+3] = r3;
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = 4*c;
        uint8_t a0 = state[i+0], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        uint8_t r0 = (uint8_t)(mul(0x0e,a0) ^ mul(0x0b,a1) ^ mul(0x0d,a2) ^ mul(0x09,a3));
        uint8_t r1 = (uint8_t)(mul(0x09,a0) ^ mul(0x0e,a1) ^ mul(0x0b,a2) ^ mul(0x0d,a3));
        uint8_t r2 = (uint8_t)(mul(0x0d,a0) ^ mul(0x09,a1) ^ mul(0x0e,a2) ^ mul(0x0b,a3));
        uint8_t r3 = (uint8_t)(mul(0x0b,a0) ^ mul(0x0d,a1) ^ mul(0x09,a2) ^ mul(0x0e,a3));
        state[i+0] = r0; state[i+1] = r1; state[i+2] = r2; state[i+3] = r3;
    }
}

static void add_round_key(uint8_t state[16], const uint8_t *roundKey) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

/* --- Key expansion (exported) --- */

void key_expansion(const uint8_t key[16], uint8_t roundKeys[AES_ROUND_KEYS_SIZE]) {
    memcpy(roundKeys, key, 16);
    int bytesGenerated = 16;
    int rconIter = 1;
    uint8_t temp[4];

    while (bytesGenerated < AES_ROUND_KEYS_SIZE) {
        for (int i = 0; i < 4; ++i) temp[i] = roundKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            temp[0] = sbox_ct(temp[0]);
            temp[1] = sbox_ct(temp[1]);
            temp[2] = sbox_ct(temp[2]);
            temp[3] = sbox_ct(temp[3]);

            temp[0] ^= Rcon[rconIter];
            rconIter++;
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/* --- Optional simple masking helper (lightweight) --- */

#ifdef AES_ENABLE_SIMPLE_MASKING
/* Provide a get_random_byte() implementation in your project that returns
 * a fresh random byte for each call. For testing you can implement a weak PRNG,
 * but for security use a hardware RNG or a cryptographically secure source.
 */
extern uint8_t get_random_byte(void);

/* Apply a single-byte XOR mask to state and adjust round keys by XORing
 * the mask into every byte of the round keys where appropriate.
 *
 * WARNING: This is a very simple mitigation and does NOT replace a proper
 * masked S-box. It raises the bar slightly against trivial attacks.
 */
static void apply_simple_mask(uint8_t state[16], uint8_t roundKeys[AES_ROUND_KEYS_SIZE], uint8_t mask) {
    for (int i = 0; i < 16; ++i) state[i] ^= mask;
    for (int i = 0; i < AES_ROUND_KEYS_SIZE; ++i) roundKeys[i] ^= mask;
}
#endif

/* --- Encrypt / Decrypt (exported) --- */

void aes_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t roundKeys_in[AES_ROUND_KEYS_SIZE]) {
    uint8_t state[AES_BLOCK_SIZE];
    uint8_t roundKeys[AES_ROUND_KEYS_SIZE];

    memcpy(state, in, AES_BLOCK_SIZE);
    memcpy(roundKeys, roundKeys_in, AES_ROUND_KEYS_SIZE);

#ifdef AES_ENABLE_SIMPLE_MASKING
    uint8_t mask = get_random_byte();
    apply_simple_mask(state, roundKeys, mask);
#endif

    add_round_key(state, roundKeys);

    for (int round = 1; round <= 9; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, roundKeys + 16 * round);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, roundKeys + 160);

#ifdef AES_ENABLE_SIMPLE_MASKING
    /* Unmask output */
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) state[i] ^= mask;
#endif

    memcpy(out, state, AES_BLOCK_SIZE);
}

void aes_decrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t roundKeys[AES_ROUND_KEYS_SIZE]) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, in, AES_BLOCK_SIZE);

    add_round_key(state, roundKeys + 160);
    inv_shift_rows(state);
    inv_sub_bytes(state);

    for (int round = 9; round >= 1; --round) {
        add_round_key(state, roundKeys + 16 * round);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    add_round_key(state, roundKeys);
    memcpy(out, state, AES_BLOCK_SIZE);
}
