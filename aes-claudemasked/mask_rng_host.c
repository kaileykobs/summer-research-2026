/*
 * mask_rng_host.c - Mask backend fed by the capture host over
 * SimpleSerial, via aes_indep_mask() in aes-independant.c.
 */
#include "mask_rng.h"

#define MASK_QUEUE_CAP 32u

static uint8_t  s_queue[MASK_QUEUE_CAP];
static unsigned s_len = 0u;
static unsigned s_pos = 0u;

static uint32_t s_fallback_state = 0xA5A5A5A5u;

volatile uint8_t mask_rng_fallback_used = 0u;

void mask_rng_seed(uint32_t seed)
{
    s_fallback_state = seed ? seed : 0xA5A5A5A5u;
}

void mask_rng_load(const uint8_t *bytes, unsigned n)
{
    unsigned i;
    if (n > MASK_QUEUE_CAP) { n = MASK_QUEUE_CAP; }
    for (i = 0u; i < n; ++i) {
        s_queue[i] = bytes[i];
    }
    s_len = n;
    s_pos = 0u;
}

static uint8_t fallback_byte(void)
{
    uint32_t x = s_fallback_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s_fallback_state = x;
    mask_rng_fallback_used = 1u;
    return (uint8_t)(x & 0xFFu);
}

uint8_t mask_rng_byte(void)
{
    if (s_pos < s_len) {
        return s_queue[s_pos++];
    }
    return fallback_byte();
}