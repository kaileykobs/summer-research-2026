/*
 * mask_rng.h - Random-byte source used to draw fresh masks.
 *
 * SECURITY-CRITICAL: the whole point of masking is that the mask is
 * unpredictable to an attacker. If mask_rng_byte() is predictable, the
 * masking buys you nothing.
 *
 * This header is implemented by mask_rng_host.c: mask bytes come from
 * the capture host via aes_indep_mask() -> mask_rng_load(), which is
 * the right source on CW-Nano since the STM32F031 has no on-chip TRNG.
 */
#ifndef MASK_RNG_H
#define MASK_RNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mask_rng_seed(uint32_t seed);
uint8_t mask_rng_byte(void);
void mask_rng_load(const uint8_t *bytes, unsigned n);
extern volatile uint8_t mask_rng_fallback_used;

#ifdef __cplusplus
}
#endif

#endif /* MASK_RNG_H */