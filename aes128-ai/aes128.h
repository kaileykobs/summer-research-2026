/*
 * aes128.h - Minimal, dependency-free AES-128 block cipher (FIPS-197).
 *
 * Single-block ECB primitive only. No dynamic allocation, no libc calls
 * inside the core (only <stdint.h>). Suitable for freestanding / embedded
 * targets. Round-key schedule is expanded once and reused per block.
 *
 * NOTE: This is a straightforward table-lookup reference implementation.
 * It is NOT constant-time and leaks through the S-box lookups and the
 * data-dependent branches in the GF multiply used by decryption. See the
 * comment block at the bottom of aes128.c before using it where timing or
 * power side channels matter.
 */
#ifndef AES128_H
#define AES128_H

#include <stdint.h>

#define AES128_KEY_SIZE      16u   /* 128-bit key                        */
#define AES_BLOCK_SIZE       16u   /* 128-bit block                      */
#define AES128_ROUNDS        10u
#define AES128_ROUND_KEYS    176u  /* (AES128_ROUNDS + 1) * AES_BLOCK_SIZE */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Expand a 16-byte key into the 176-byte round-key schedule.
 * Call once per key; the schedule can then be reused for many blocks.
 */
void aes128_key_expansion(const uint8_t key[AES128_KEY_SIZE],
                          uint8_t round_keys[AES128_ROUND_KEYS]);

/*
 * Encrypt / decrypt a single 16-byte block.
 * `in` and `out` may alias (point to the same buffer).
 */
void aes128_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                          uint8_t out[AES_BLOCK_SIZE],
                          const uint8_t round_keys[AES128_ROUND_KEYS]);

void aes128_decrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                          uint8_t out[AES_BLOCK_SIZE],
                          const uint8_t round_keys[AES128_ROUND_KEYS]);

#ifdef __cplusplus
}
#endif

#endif /* AES128_H */
