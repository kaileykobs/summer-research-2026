/* aes.h - AES-128 single-block API (firmware-safe)
 *
 * Public header for aes128_block.c
 * Place this in your include path and include from aes-independant.c
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Size of one AES block in bytes */
#define AES_BLOCK_SIZE 16

/** Size of expanded round keys for AES-128 in bytes (11 round keys * 16 bytes) */
#define AES_ROUND_KEYS_SIZE 176

/* Optional lightweight masking support
 * Define AES_ENABLE_SIMPLE_MASKING in your build to enable the simple mask
 * wrapper in aes128_block.c. If enabled, you must provide get_random_byte().
 */
 #define AES_ENABLE_SIMPLE_MASKING 

#ifdef AES_ENABLE_SIMPLE_MASKING
/* Provide a function that returns a fresh random byte per call */
uint8_t get_random_byte(void);
#endif

/* Expand a 16-byte AES-128 key into AES_ROUND_KEYS_SIZE bytes of round keys.
 * key       - pointer to 16-byte key
 * roundKeys - pointer to buffer of at least AES_ROUND_KEYS_SIZE bytes
 */
void key_expansion(const uint8_t key[16], uint8_t roundKeys[AES_ROUND_KEYS_SIZE]);

/* Encrypt a single 16-byte block.
 * in        - pointer to 16-byte plaintext
 * out       - pointer to 16-byte buffer for ciphertext
 * roundKeys - pointer to expanded round keys (AES_ROUND_KEYS_SIZE bytes)
 */
void aes_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t roundKeys[AES_ROUND_KEYS_SIZE]);

/* Decrypt a single 16-byte block.
 * in        - pointer to 16-byte ciphertext
 * out       - pointer to 16-byte buffer for plaintext
 * roundKeys - pointer to expanded round keys (AES_ROUND_KEYS_SIZE bytes)
 */
void aes_decrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t roundKeys[AES_ROUND_KEYS_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* AES_H */
