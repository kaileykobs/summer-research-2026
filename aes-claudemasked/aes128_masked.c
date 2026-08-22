/*
 * aes128_masked.c - First-order Boolean-masked AES-128.
 * See aes128_masked.h for the security model, what it does and does not
 * protect, and the invariant this file relies on.
 */
#include "aes128_masked.h"
#include "mask_rng.h"

/* Reuse the tables from aes128.c (now non-static there) instead of
 * paying another 512 bytes of flash for a second copy. */
extern const uint8_t sbox[256];
extern const uint8_t rsbox[256];

/* ---- GF(2^8) arithmetic (poly 0x11b), local copies to keep this file
 * self-contained -------------------------------------------------------- */
static uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ (((a >> 7) & 1u) * 0x1bu));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0u;
    uint8_t i;
    for (i = 0u; i < 8u; ++i) {
        p ^= (uint8_t)((b & 1u) ? a : 0u);
        {
            uint8_t hi = (uint8_t)(a & 0x80u);
            a = (uint8_t)(a << 1);
            if (hi) { a ^= 0x1bu; }
        }
        b = (uint8_t)(b >> 1);
    }
    return p;
}

/*
 * Build a masked S-box: table[x ^ m_in] = sbox[x] ^ m_out for every x.
 * Then for any byte v = true_v ^ m_in, table[v] == sbox[true_v] ^ m_out -
 * the true value `true_v` never has to be formed to get that result.
 *
 * Cost: 256 table writes, done fresh once per round. On a Cortex-M0 at a
 * few MHz that's well under the per-block time the unmasked cipher
 * already takes; it is not the expensive part of this design.
 */
static void build_masked_sbox(uint8_t table[256], uint8_t m_in, uint8_t m_out)
{
    unsigned x;
    for (x = 0u; x < 256u; ++x) {
        table[(uint8_t)((uint8_t)x ^ m_in)] = (uint8_t)(sbox[(uint8_t)x] ^ m_out);
    }
}

static void build_masked_rsbox(uint8_t table[256], uint8_t m_in, uint8_t m_out)
{
    unsigned x;
    for (x = 0u; x < 256u; ++x) {
        table[(uint8_t)((uint8_t)x ^ m_in)] = (uint8_t)(rsbox[(uint8_t)x] ^ m_out);
    }
}

/*
 * Masked SubBytes over the whole 16-byte share, single shared mask.
 * s[] holds true[i] ^ m_in on entry; on return it holds true'[i] ^ m_out
 * (m_out chosen fresh here) and m_out is returned. No sbox[true[i]] value
 * is ever computed directly - only table[share[i]], where share[i] is
 * already masked.
 */
static uint8_t masked_sub_bytes(uint8_t s[16], uint8_t m_in)
{
    uint8_t table[256];
    uint8_t m_out = mask_rng_byte();
    unsigned i;
    build_masked_sbox(table, m_in, m_out);
    for (i = 0u; i < 16u; ++i) {
        s[i] = table[s[i]];
    }
    return m_out;
}

static uint8_t masked_inv_sub_bytes(uint8_t s[16], uint8_t m_in)
{
    uint8_t table[256];
    uint8_t m_out = mask_rng_byte();
    unsigned i;
    build_masked_rsbox(table, m_in, m_out);
    for (i = 0u; i < 16u; ++i) {
        s[i] = table[s[i]];
    }
    return m_out;
}

/* ---- Linear steps, operating on the flat 16-byte share -----------------
 * These are identical in effect to the state_t versions in aes128.c; a
 * uniform mask commutes through both (ShiftRows trivially, MixColumns
 * because every row of the AES mix matrix XORs to 0x01 - see header). */

/* Row-major index convention matching aes128.c's column-major state:
 * s[c*4 + r] == state[r][c]. */

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    unsigned i;
    for (i = 0u; i < 16u; ++i) {
        s[i] ^= rk[i];
    }
}

static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    /* row 1 (indices 1,5,9,13): left by 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* row 2 (indices 2,6,10,14): left by 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3 (indices 3,7,11,15): left by 3 (== right by 1) */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void mix_columns(uint8_t s[16])
{
    unsigned c;
    for (c = 0u; c < 4u; ++c) {
        uint8_t *col = &s[4u * c];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(xtime(a0) ^ (uint8_t)(xtime(a1) ^ a1) ^ a2 ^ a3);
        col[1] = (uint8_t)(a0 ^ xtime(a1) ^ (uint8_t)(xtime(a2) ^ a2) ^ a3);
        col[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (uint8_t)(xtime(a3) ^ a3));
        col[3] = (uint8_t)((uint8_t)(xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void inv_mix_columns(uint8_t s[16])
{
    unsigned c;
    for (c = 0u; c < 4u; ++c) {
        uint8_t *col = &s[4u * c];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3, 9));
        col[1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
        col[2] = (uint8_t)(gmul(a0,13) ^ gmul(a1, 9) ^ gmul(a2,14) ^ gmul(a3,11));
        col[3] = (uint8_t)(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2, 9) ^ gmul(a3,14));
    }
}

/* ---- Block API ----------------------------------------------------------
 * Note the byte order here (s[c*4+r]) already matches how aes128.h's
 * `in`/`out` arrays are laid out relative to aes128.c's state_t, so we can
 * copy in/out flat with no transpose. */

void aes128_encrypt_block_masked(const uint8_t in[AES_BLOCK_SIZE],
                                 uint8_t out[AES_BLOCK_SIZE],
                                 const uint8_t rk[AES128_ROUND_KEYS])
{
    uint8_t s[16];
    uint8_t m;
    unsigned i, round;

    /* Mask the plaintext before it ever touches state. Forming
     * `in[i] ^ m` combines a random byte with the true input, so the
     * result is uniformly random from an observer's point of view even
     * though `in[i]` itself is not secret here - the point is that from
     * this line on, every stored byte is a share, never a true value. */
    m = mask_rng_byte();
    for (i = 0u; i < 16u; ++i) {
        s[i] = (uint8_t)(in[i] ^ m);
    }

    add_round_key(s, rk); /* m unchanged: XORing a public constant into a masked share stays masked */

    for (round = 1u; round < AES128_ROUNDS; ++round) {
        m = masked_sub_bytes(s, m);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk + 16u * round);
    }

    m = masked_sub_bytes(s, m);
    shift_rows(s);
    add_round_key(s, rk + 16u * AES128_ROUNDS);

    for (i = 0u; i < 16u; ++i) {
        out[i] = (uint8_t)(s[i] ^ m);
    }
}

void aes128_decrypt_block_masked(const uint8_t in[AES_BLOCK_SIZE],
                                 uint8_t out[AES_BLOCK_SIZE],
                                 const uint8_t rk[AES128_ROUND_KEYS])
{
    uint8_t s[16];
    uint8_t m;
    unsigned i;
    int round;

    m = mask_rng_byte();
    for (i = 0u; i < 16u; ++i) {
        s[i] = (uint8_t)(in[i] ^ m);
    }

    add_round_key(s, rk + 16u * AES128_ROUNDS);

    for (round = (int)AES128_ROUNDS - 1; round >= 1; --round) {
        inv_shift_rows(s);
        m = masked_inv_sub_bytes(s, m);
        add_round_key(s, rk + 16u * (unsigned)round);
        inv_mix_columns(s);
    }

    inv_shift_rows(s);
    m = masked_inv_sub_bytes(s, m);
    add_round_key(s, rk);

    for (i = 0u; i < 16u; ++i) {
        out[i] = (uint8_t)(s[i] ^ m);
    }
}
