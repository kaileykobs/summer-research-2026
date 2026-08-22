#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16

// AES-128 uses 10 rounds; key expansion produces 11 round keys (176 bytes)
typedef struct {
    uint8_t round_keys[176];
} AES128_Context;

// Initialize context with a 16-byte key
void aes128_init(AES128_Context *ctx, const uint8_t key[16]);

// Encrypt a single 16-byte block
void aes128_encrypt_block(const AES128_Context *ctx, const uint8_t in[16], uint8_t out[16]);

// Decrypt a single 16-byte block
void aes128_decrypt_block(const AES128_Context *ctx, const uint8_t in[16], uint8_t out[16]);

#endif // AES128_H