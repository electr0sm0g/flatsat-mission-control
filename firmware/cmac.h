/*  - cmac.h
 *
 * flatsat-lab vulnerable firmware v2 -- AES-CMAC (NIST SP 800-38B) and
 * AES-CTR helpers built on secure_link's AES-128 core (arbitrary key).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_CMAC_H
#define FIRMWARE_CMAC_H
#include <Arduino.h>

/* AES-CMAC over data[0..len) with the given 16-byte key. */
void labCmac(const uint8_t *key, const uint8_t *data, size_t len,
             uint8_t mac[16]);

/* AES-CTR keystream XOR, 16-byte aligned length. counter_block is
 * incremented as a 128-bit big-endian integer between blocks. */
void labCtrXor(const uint8_t *key, const uint8_t counter_block[16],
               const uint8_t *in, uint8_t *out, size_t len);

#endif // FIRMWARE_CMAC_H
