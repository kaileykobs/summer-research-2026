/*
 * aes128_masked.h - First-order Boolean-masked AES-128 block cipher.
 *
 * Same interface shape as aes128.h, but the block functions never let a
 * true (unmasked) intermediate state byte sit in memory during SubBytes,
 * the operation that unprotected table-lookup AES leaks through on
 * power/EM side channels.
 *
 * WHAT'S PROTECTED
 *   - The 16-byte cipher STATE is kept as `share[i] = true[i] ^ m` for a
 *     single random byte `m` shared across the whole state. SubBytes is
 *     done through a masked S-box table that is rebuilt with a fresh
 *     random output mask before every round, so no S-box input or output
 *     byte ever appears in the clear.
 *   - ShiftRows and MixColumns are GF(2)-linear, and the standard AES
 *     MixColumns matrix has the property that every row's coefficients
 *     XOR to 0x01. That means a *uniform* mask (same byte in all 16
 *     positions) is a fixed point of both operations, so `m` propagates
 *     through them unchanged with no extra bookkeeping and no separate
 *     "mask state" to maintain.
 *   - AddRoundKey XORs a public round-key byte into an already-masked
 *     share; that's safe on its own (XORing a constant into a uniformly
 *     masked value keeps it uniformly masked).
 *
 * WHAT'S NOT PROTECTED (read this before you trust it)
 *   - Key expansion (aes128_key_expansion, reused unmodified from
 *     aes128.c) runs the master key through the S-box in the clear to
 *     build the schedule. If your setup captures traces during key
 *     expansion - or expands the key inline before every encryption
 *     instead of once - that step is just as leaky as the unmasked
 *     implementation, independent of anything here. Masking the schedule
 *     itself needs masked round-key storage carried all the way through
 *     AddRoundKey, which is a bigger change than this file makes; ask if
 *     you want that next.
 *   - This is FIRST-ORDER masking only: one mask share, protecting
 *     against a single-sample (univariate) CPA/DPA attack on any one
 *     leakage point. It is not proven secure against second-order
 *     attacks that combine two leakage samples (e.g. the SubBytes input
 *     and output within the same round), and the CW-Nano's SNR is high
 *     enough that a determined second-order attack (or just more traces
 *     against a weak mask source) can still work.
 *   - Security is entirely contingent on mask_rng_byte() being
 *     unpredictable. See mask_rng.h.
 *   - InvMixColumns (decrypt path) still uses the branching gmul() from
 *     aes128.c; the value it branches on is now a masked share rather
 *     than the true byte, which removes the direct key-recovery timing
 *     leak, but a branch-free multiply is still better practice.
 *
 * In short: this raises the bar from "trivial CPA target" to "needs a
 * higher-order or mask-recovery attack, and a leaky key schedule is a
 * separate hole to close" - which is exactly the kind of target CW-Nano
 * masking labs are built around. It is a teaching/research-grade
 * countermeasure, not a certified one.
 */
#ifndef AES128_MASKED_H
#define AES128_MASKED_H

#include "aes128.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encrypt / decrypt a single 16-byte block with first-order masked
 * SubBytes. `in`/`out` may alias. `rk` is the standard unmasked round-key
 * schedule from aes128_key_expansion().
 */
void aes128_encrypt_block_masked(const uint8_t in[AES_BLOCK_SIZE],
                                 uint8_t out[AES_BLOCK_SIZE],
                                 const uint8_t rk[AES128_ROUND_KEYS]);

void aes128_decrypt_block_masked(const uint8_t in[AES_BLOCK_SIZE],
                                 uint8_t out[AES_BLOCK_SIZE],
                                 const uint8_t rk[AES128_ROUND_KEYS]);

#ifdef __cplusplus
}
#endif

#endif /* AES128_MASKED_H */
