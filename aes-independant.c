/*
    This file is part of the AESExplorer Example Targets
    Copyright (C) 2012 Colin O'Flynn <coflynn@newae.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "aes-independant.h"
#include "hal.h"

#if HWCRYPTO

void aes_indep_init(void)
{
    HW_AES128_Init();
}

void aes_indep_key(uint8_t * key)
{
    HW_AES128_LoadKey(key);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    HW_AES128_Enc_pretrigger(pt);
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    HW_AES128_Enc_posttrigger(pt);
}

void aes_indep_enc(uint8_t * pt)
{
    HW_AES128_Enc(pt);
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(AVRCRYPTOLIB)
#include "aes128_enc.h"
#include "aes_keyschedule.h"

aes128_ctx_t ctx;

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
	aes128_init(key, &ctx);
}

void aes_indep_enc(uint8_t * pt)
{
	aes128_enc(pt, &ctx); /* encrypting the data block */
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(SIMPLEAES)

uint8_t enckey[16];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
	for(uint8_t i=0; i < 16; i++){
		enckey[i] = key[i];
	}
}

void aes_indep_enc(uint8_t * pt)
{
	uint8_t * result = aes(pt, enckey);
	for(uint8_t i=0; i < 16; i++){
		pt[i] = result[i];
	}
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(DPAV4)

#include "aes.h"
#include "aes_enc.h"

/*  This is the AES RSM 256 encryption function that call the generic AES RSM encryption core*/
void aes256_enc(uint8_t* j, void* buffer, aes256_ctx_t* ctx,uint8_t rng){
	aes_encrypt_core(j,buffer, (aes_genctx_t*)ctx, 14,(uint8_t)rng);
}

aes256_ctx_t ctx;

void aes_indep_init(void)
{
    ;
}

void aes_indep_key(uint8_t * key)
{
	aes256_init(key, &ctx);
}

void aes_indep_enc(uint8_t * pt)
{
	static uint8_t j[0];

	//Encryption with trigger enabled
	aes256_enc(j, pt, &ctx, 1);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(TINYAES128C)

#include "aes.h"

uint8_t enckey[16];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    AES128_ECB_indp_setkey(key);
}

void aes_indep_enc(uint8_t * pt)
{
	AES128_ECB_indp_crypto(pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(SHUFFLEDAES)

#include "aes.h"

uint8_t enckey[16];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    AES128_ECB_indp_setkey(key);
}

void aes_indep_enc(uint8_t * pt)
{
	AES128_ECB_indp_crypto(pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(AES128ECBHEADER)

#include "aes.h"

AES_CTX ctx;

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    AES_EncryptInit(&ctx, key);
}

void aes_indep_enc(uint8_t * pt)
{
    AES_Encrypt(&ctx, pt, 16, pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt) { ; }
void aes_indep_enc_posttrigger(uint8_t * pt) { ; }
void aes_indep_mask(uint8_t * m, uint8_t len) { }

#elif defined(MASKEDCENSUS)

#include "aes.h"

struct AES_ctx ctx;

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    AES_init_ctx(&ctx, key);
}

void aes_indep_enc(uint8_t * pt)
{
	AES_ECB_encrypt(&ctx, pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}


#elif defined(AES128AI)

#include "aes128.h"

static uint8_t round_keys[AES128_ROUND_KEYS];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    aes128_key_expansion(key, round_keys);
}

void aes_indep_enc(uint8_t * pt)
{
    aes128_encrypt_block(pt, pt, round_keys);   // in/out can alias, per the header's own docs
}

void aes_indep_enc_pretrigger(uint8_t * pt) { ; }
void aes_indep_enc_posttrigger(uint8_t * pt) { ; }
void aes_indep_mask(uint8_t * m, uint8_t len) { }



#if defined(DHUERTASAES)
#include "aes.h"

static uint8_t *roundkey;
static uint8_t aes_key_buf[16]; // adjust size if you switch to AES-192/256

void aes_indep_init(void)
{
    // nothing needed here for this implementation
}

void aes_indep_key(uint8_t * key)
{
    memcpy(aes_key_buf, key, 16);
    roundkey = aes_init(sizeof(aes_key_buf));   // allocates + sets Nk/Nr
    aes_key_expansion(aes_key_buf, roundkey);
}

void aes_indep_enc(uint8_t * pt)
{
    uint8_t ct[16];
    aes_cipher(pt, ct, roundkey);
    memcpy(pt, ct, 16); // aes_indep_enc is expected to return ciphertext in-place
}
#endif

#elif defined(GEMINI)

#include "aes128.h"

static AES128_Context ctx;

void aes_indep_init(void)
{
    // No special initialization required
}

void aes_indep_key(uint8_t * key)
{
    // Perform key expansion using the 16-byte key
    aes128_init(&ctx, key);
}

void aes_indep_enc(uint8_t * pt)
{
    // Encrypt the 16-byte block in-place (overwrites pt with ciphertext)
    aes128_encrypt_block(&ctx, pt, pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    // Optional: add pre-capture code here if needed
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    // Optional: add post-capture code here if needed
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
    // Unused for unmasked implementations
}

#elif defined(GEMINIMASKED)

#include "aes_masked.h"

static AESMasked_Context ctx;

void aes_indep_init(void) {
    aes_masked_set_mask(&ctx, 0xAA, 0x55); // Default initial masks
}

void aes_indep_key(uint8_t * key) {
    // Key setup logic
}

void aes_indep_enc(uint8_t * pt) {
    aes_masked_encrypt_block(&ctx, pt);
}

void aes_indep_mask(uint8_t * m, uint8_t len) {
    if (len >= 2) {
        // Receives random masks passed from Python (e.g., target.set_mask(...))
        aes_masked_set_mask(&ctx, m[0], m[1]);
    }
}

void aes_indep_enc_pretrigger(uint8_t * pt) {}
void aes_indep_enc_posttrigger(uint8_t * pt) {}

#elif defined(COPILOT)

/* Custom AES-128 block cipher implementation */
#include "aes.h"   // <-- Your AES header

static uint8_t roundKeys[AES_ROUND_KEYS_SIZE];

void aes_indep_init(void)
{
    // No special init needed
}

void aes_indep_key(uint8_t * key)
{
    // Expand the 16‑byte AES key
    key_expansion(key, roundKeys);
}

void aes_indep_enc(uint8_t * pt)
{
    // Encrypt the block in-place
    aes_encrypt_block(pt, pt, roundKeys);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    // Optional hook
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    // Optional hook
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
    // Unused for this implementation
}

#elif defined(COPILOTMASKED)

#include "aes.h"
#include <string.h>
#include <stdint.h>

#ifdef AES_ENABLE_SIMPLE_MASKING
uint8_t get_random_byte(void)
{
    static uint32_t x = 0x12345678;   // simple LCG seed
    x = x * 1664525 + 1013904223;     // LCG
    return (uint8_t)(x >> 24);
}
#endif


/* Round keys buffer used by this backend */
static uint8_t roundKeys[AES_ROUND_KEYS_SIZE];

void aes_indep_init(void)
{
    /* No special initialization required for this implementation */
}

/* Load and expand the 16-byte key into roundKeys */
void aes_indep_key(uint8_t * key)
{
    key_expansion(key, roundKeys);
}

/* Encrypt a single 16-byte block in-place */
void aes_indep_enc(uint8_t * pt)
{
    uint8_t tmp_out[AES_BLOCK_SIZE];
    aes_encrypt_block(pt, tmp_out, roundKeys);
    memcpy(pt, tmp_out, AES_BLOCK_SIZE);
}

/* Optional hooks used by the test harness; keep them empty if unused */
void aes_indep_enc_pretrigger(uint8_t * pt)
{
    /* Optional: place any pre-trigger instrumentation here */
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    /* Optional: place any post-trigger instrumentation here */
}

/* Optional: receive mask bytes from the test harness (unused for unmasked impl) */
void aes_indep_mask(uint8_t * m, uint8_t len)
{
    (void)m;
    (void)len;
}


#elif defined(CLAUDEMASKED)

#include "aes128.h"
#include "aes128_masked.h"
#include "mask_rng.h"

/* Bytes consumed per aes_indep_enc(): 1 initial state mask + 1 fresh
 * output mask per SubBytes call across 10 rounds = 11. Send at least
 * this many bytes with aes_indep_mask() before every encrypt. */
#define CLAUDEMASKED_MASKSIZE 11u

static uint8_t round_keys[AES128_ROUND_KEYS];

void aes_indep_init(void)
{
    mask_rng_seed(0xC0FFEEu); /* seeds the emergency fallback only */
}

void aes_indep_key(uint8_t * key)
{
    aes128_key_expansion(key, round_keys);
}

void aes_indep_enc(uint8_t * pt)
{
    aes128_encrypt_block_masked(pt, pt, round_keys);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
    mask_rng_load(m, len);
}


#elif defined(MBEDTLS)
#include "mbedtls/aes.h"

mbedtls_aes_context ctx;

void aes_indep_init(void)
{
	mbedtls_aes_init(&ctx);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_key(uint8_t * key)
{
	mbedtls_aes_setkey_enc(&ctx, key, 128);
}

void aes_indep_enc(uint8_t * pt)
{
	mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, pt, pt); /* encrypting the data block */
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(MASKEDAES)

#if defined(ANSSI_AVR)

#include "aesTables.h"
#include "maskedAES128enc.h"

void aes_indep_init(void)
{
}

void aes_indep_key(uint8_t * key)
{
  int i;
  for (i = 0; i < AESKeySize; i++)
    secret[i] = key[i];
}

void aes_indep_enc(uint8_t * pt)
{
  asm_maskedAES128enc();
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
  int i;
  for (i = 0; i < AESInputSize; i++)
    input[i] = pt[i];
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    int i;
  for (i = 0; i < AESOutputSize; i++)
    pt[i] = input[i];
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
  int i;
  for (i = 0; i < AESMaskSize; i++)
    mask[i] = m[i];
}

#elif defined(ANSSI_CM4)

#include "platform.h"
#include "string.h"
#include "aes.h"

#ifndef NULL
#define NULL 0
#endif

#define AESKeySize 16
#define AESMaskSize 19
#define AESBlockSize 16

STRUCT_AES aes_ctx;
uint8_t key_mask[AESMaskSize];
uint8_t aes_mask[AESMaskSize];
uint8_t temp_key[AESKeySize];
uint8_t mask_modes;

void aes_indep_init(void)
{
  local_memset(&aes_ctx, 0, sizeof(aes_ctx));
  mask_modes = 0;
}

void aes_indep_key(uint8_t* key)
{
#ifdef TRIG_BEFORE_KS
  int i;
  for (i = 0; i < AESKeySize; i++)
    temp_key[i] = key[i];
#else
  aes(MODE_KEYINIT | mask_modes, &aes_ctx, key,
      NULL /* plaintext */, NULL /* encrypted text */,
      aes_mask, key_mask);
#endif
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
}

void aes_indep_enc(uint8_t* pt)
{
#ifdef TRIG_BEFORE_KS
  aes(MODE_KEYINIT | MODE_AESINIT_ENC | MODE_ENC | mask_modes,
      &aes_ctx, temp_key,
      pt /* plaintext */, pt /* encrypted text */,
      aes_mask, key_mask);
#else
  aes(MODE_AESINIT_ENC | MODE_ENC | mask_modes, &aes_ctx, NULL /* key */,
      pt /* plaintext */, pt /* encryted text */,
      aes_mask, key_mask);
#endif
}

void aes_indep_mask(uint8_t* m, uint8_t len)
{
  int i;
  if (len >= AESMaskSize) {
    for (i = 0; i < AESMaskSize; i++)
      key_mask[i] = m[i];
    mask_modes |= MODE_RANDOM_KEY_EXT;
  } else {
    mask_modes &= ~MODE_RANDOM_KEY_EXT;
  }

  if (len == (2 * AESMaskSize)) {
    for (i = 0; i < AESMaskSize; i++)
      aes_mask[i] = m[i + AESMaskSize];
    mask_modes |= MODE_RANDOM_AES_EXT;
  } else {
    mask_modes &= ~MODE_RANDOM_AES_EXT;
  }
}

#elif defined(RIOUBSAES)

#include "secure_aes_pbs.h"

uint8_t encKey[16];

bitslice_t get_random_bitslice(void)
{
  return get_rand();
}

void aes_indep_init(void)
{
}

void aes_indep_key(uint8_t * key)
{
  for (uint8_t i = 0; i < 16; i++) {
    encKey[i] = key[i];
  }
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
}

void aes_indep_enc(uint8_t * pt)
{
  sec_aes128_enc_packed_bitslice_wrapper(pt, pt, encKey);
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#elif defined(KNARFRANKBSAES)

#include "masked_combined.h"

uint8_t encKey[16];

int rand(void)
{
  return get_rand();
}

void aes_indep_init(void)
{
}

void aes_indep_key(uint8_t * key)
{
  for (uint8_t i = 0; i < 16; i++) {
    encKey[i] = key[i];
  }
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
}

void aes_indep_enc(uint8_t * pt)
{
  uint8_t result[16];
  Encrypt(result, pt, encKey);
  for (uint8_t i = 0; i < 16; i++) {
    pt[i] = result[i];
  }
}

void aes_indep_mask(uint8_t * m, uint8_t len)
{
}

#else

#error "Unsupported MASKEDAES implementation"

#endif // MASKEDAES

#else

#error "No Crypto Lib Defined?"

#endif


