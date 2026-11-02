/*  - sdls_sim.h
 *
 * flatsat-lab vulnerable firmware v2 -- Space Data Link Security (CCSDS
 * 355.0-B-2) simulation mirroring the ESA CryptoLib failure modes that the
 * course chapters 3 and 7 dissect (CVE-2024-44910/-44911/-44912 patterns):
 *
 *   - 64-entry SA table, only 21 entries configured (ast/est), the other
 *     43 are all-zero => "SA_PLAINTEXT" pass-through (no MAC, no ARC);
 *   - get_sa_from_spi() with no bounds check: SPI 64..8998 lands on the
 *     zeroed arena right behind the table -> accepted as plaintext;
 *     SPI >= 9000 falls off the mapped arena -> fault / hang (DoS);
 *   - anti-replay counter (ARC) volatile in SRAM, parameterised width
 *     (16/20/32 bits) and acceptance window W (default 5), reset to zero
 *     on every boot => capture/replay after reset works (course ch.3.1);
 *   - 128 master keys all-zero at boot, OTAR validates only m_idx < 128:
 *     no state, no length -> an adversary posts their session key under
 *     the null master key and expropriates the operator (course ch.7.2);
 *   - KEY_VERIFY oracle: encrypts the attacker-chosen 16-byte body with
 *     the SA key in CTR mode using an attacker-chosen counter block and
 *     no freshness check -> keystream-reuse plaintext recovery (ch.7.2).
 *
 * The Python simulator (flatsat-lab/simulator) implements the byte-for-byte
 * mirror of everything here; the host test-suite pins the crypto vectors.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_SDLS_SIM_H
#define FIRMWARE_SDLS_SIM_H
#include "spp.h"
#include <Arduino.h>

#define SDLS_NUM_SA 64
#define SDLS_NUM_SA_CONFIGURED 21 /* sa[0..20] configured; 43 zero SA_PLAINTEXT */
#define SDLS_SA_PLAINTEXT_DEFAULT 44
#define SDLS_NUM_MASTER_KEYS 128
#define SDLS_SPI_FAULT 9000 /* first SPI whose unbounded read faults */
#define SDLS_SEC_HEADER_LEN 22 /* SPI(2) | ARC(4) | MAC(16) */

typedef enum {
  SDLS_OK = 0,           /* authenticated, payload decrypted-ready */
  SDLS_PASS = 1,         /* accepted through a Clear/SA_PLAINTEXT path */
  SDLS_REJECT_MAC = 2,
  SDLS_REJECT_ARC = 3,
  SDLS_REJECT_HDR = 4,   /* SA demands security, none present */
  SDLS_HANG = 5,         /* unbounded SPI -> fault */
} sdls_result_t;

typedef struct {
  uint8_t est; /* encryption required on payload */
  uint8_t ast; /* authentication required (MAC + ARC) */
  uint8_t key[16];
} sdls_sa_t;

/* config / state */
void sdlsConfigure(uint8_t mode, uint8_t arc_bits, uint8_t window);
bool sdlsIsEnabled(void);
uint8_t sdlsArcBits(void);
uint8_t sdlsWindow(void);
uint32_t sdlsArcValue(void);
void sdlsArcReset(void);                /* boot / brownout (V-07) */
void sdlsSetArcRelaxed(bool relaxed);   /* FDIR contingency: W -> 15 (V-22) */
bool sdlsArcRelaxed(void);
void sdlsBootDefaults(void);            /* called from labBootInit */

/* table access */
const sdls_sa_t *sdlsResolveSa(uint16_t spi, bool *out_of_bounds);
const sdls_sa_t *sdlsGetSa(uint8_t idx);
bool sdlsSaSet(uint8_t sa_idx, uint8_t est, uint8_t ast, const uint8_t key[16]);
bool sdlsOtar(uint8_t m_idx, uint8_t sa_idx, const uint8_t ct[16],
              uint8_t installed_key_out[16]);
const uint8_t *sdlsMasterKeyNullCount(uint8_t *count_out);

/* uplink security processing (RADIO source only; USB is trusted local bus) */
sdls_result_t sdlsPreProcess(space_packet_t *space_packet, bool radio_source);

/* oracle (APID 0x17): out = body XOR E_key(ctr_block) [CTR, reuse-prone] */
void sdlsKeyVerify(uint8_t key_id, const uint8_t ctr[4], const uint8_t body[16],
                   uint8_t out[16]);

#endif // FIRMWARE_SDLS_SIM_H
