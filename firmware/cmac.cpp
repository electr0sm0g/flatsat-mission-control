/*  - cmac.cpp
 *
 * NIST SP 800-38B AES-CMAC. Subkeys: L = E(K, 0^128);
 * K1 = L << 1 (x^11011 conditionally), K2 = K1 << 1.
 * Verifies against SP 800-38B D.1 vectors (host test suite,
 * flatsat-lab/tests/host).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "cmac.h"
#include "secure_link.h"
#include <string.h>

static void shift_left_128(uint8_t v[16]) {
  for (int i = 0; i < 15; i++) {
    v[i] = (uint8_t)((v[i] << 1) | (v[i + 1] >> 7));
  }
  v[15] = (uint8_t)(v[15] << 1);
}

static void cmac_subkeys(const uint8_t *key, uint8_t k1[16], uint8_t k2[16]) {
  static const uint8_t zero[16] = {0};
  uint8_t l[16];
  secureLinkEncryptBlockAnyKey(key, zero, l);

  memcpy(k1, l, 16);
  const uint8_t msb = (uint8_t)(k1[0] >> 7);
  shift_left_128(k1);
  if (msb) {
    k1[15] ^= 0x87; /* Rb for 128-bit block */
  }

  memcpy(k2, k1, 16);
  const uint8_t msb2 = (uint8_t)(k2[0] >> 7);
  shift_left_128(k2);
  if (msb2) {
    k2[15] ^= 0x87;
  }
}

void labCmac(const uint8_t *key, const uint8_t *data, size_t len,
             uint8_t mac[16]) {
  uint8_t k1[16], k2[16];
  cmac_subkeys(key, k1, k2);

  /* n = number of blocks, last block complete? */
  const size_t n = (len + 15) / 16;
  uint8_t x[16] = {0};
  uint8_t y[16];
  size_t offset = 0;

  if (len == 0) {
    /* n = 0, empty message treated as 1 incomplete padded block */
    memset(y, 0, sizeof(y));
    y[0] = 0x80;
    for (int i = 0; i < 16; i++) {
      y[i] ^= k2[i];
    }
    for (int i = 0; i < 16; i++) {
      y[i] ^= x[i];
    }
    secureLinkEncryptBlockAnyKey(key, y, mac);
    return;
  }

  if (len % 16 == 0) {
    /* complete last block -> K1 */
    for (size_t block = 0; block + 1 < n; block++) {
      for (int i = 0; i < 16; i++) {
        y[i] = data[offset + i] ^ x[i];
      }
      secureLinkEncryptBlockAnyKey(key, y, x);
      offset += 16;
    }
    for (int i = 0; i < 16; i++) {
      y[i] = data[offset + i] ^ k1[i] ^ x[i];
    }
    secureLinkEncryptBlockAnyKey(key, y, mac);
    return;
  }

  /* incomplete last block: 0x80 padding -> K2 */
  for (size_t block = 0; block + 1 < n; block++) {
    for (int i = 0; i < 16; i++) {
      y[i] = data[offset + i] ^ x[i];
    }
    secureLinkEncryptBlockAnyKey(key, y, x);
    offset += 16;
  }
  memset(y, 0, sizeof(y));
  memcpy(y, data + offset, len - offset);
  y[len - offset] = 0x80;
  for (int i = 0; i < 16; i++) {
    y[i] ^= k2[i] ^ x[i];
  }
  secureLinkEncryptBlockAnyKey(key, y, mac);
}

void labCtrXor(const uint8_t *key, const uint8_t counter_block[16],
               const uint8_t *in, uint8_t *out, size_t len) {
  uint8_t ctr[16];
  uint8_t ks[16];
  memcpy(ctr, counter_block, 16);

  for (size_t offset = 0; offset < len; offset += 16) {
    secureLinkEncryptBlockAnyKey(key, ctr, ks);
    const size_t chunk = (len - offset < 16) ? (len - offset) : 16;
    for (size_t i = 0; i < chunk; i++) {
      out[offset + i] = in[offset + i] ^ ks[i];
    }
    /* increment big-endian 128-bit counter */
    for (int i = 15; i >= 0; i--) {
      ctr[i] = (uint8_t)(ctr[i] + 1);
      if (ctr[i] != 0) {
        break;
      }
    }
  }
}
