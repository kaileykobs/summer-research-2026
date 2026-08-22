#ifndef AES_MASKED_H
#define AES_MASKED_H

#include <stdint.h>

typedef struct {
    uint8_t round_keys[176];
    uint8_t mask_in;   // Mask applied to input data
    uint8_t mask_out;  // Mask applied to output data
} AESMasked_Context;

void aes_masked_init(AESMasked_Context *ctx, const uint8_t key[16]);
void aes_masked_set_mask(AESMasked_Context *ctx, uint8_t in_mask, uint8_t out_mask);
void aes_masked_encrypt_block(AESMasked_Context *ctx, uint8_t state[16]);

#endif