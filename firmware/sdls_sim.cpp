/*  - sdls_sim.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Mirror of this file's behaviour in Python:
 *   flatsat-lab/simulator/flatsat_sim.py :: class Sdls
 */
#include "sdls_sim.h"
#include "cmac.h"
#include "secure_link.h"
#include <string.h>

/* Volatile-by-design: this whole table lives in .bss, cleared at every
 * boot. Exactly the CryptoLib failure the course describes -- SA keys and
 * the ARC are not in battery-backed RAM, so a reset (or brownout, or the
 * unauthenticated RESETC) rewinds the security state of the spacecraft. */
static sdls_sa_t s_sa[SDLS_NUM_SA];

/* The "zeroed arena" behind the table. In the real CryptoLib bug the OOB
 * read walks into whatever memory follows the SA array; here that memory
 * is deliberately zeroed so a bounded sweep of SPIs 64..8999 behaves the
 * way the course numbers predict (plaintext pass, CRYPTO_LIB_SUCCESS). */
static const sdls_sa_t s_zero_sa = {0, 0, {0}};

static uint8_t s_master_keys[SDLS_NUM_MASTER_KEYS][16]; /* all-zero at boot */

static bool s_enabled = false;
static uint8_t s_arc_bits = 16;
static uint8_t s_window = 5;
static bool s_arc_relaxed = false;
static uint32_t s_arc_last = 0;

void sdlsBootDefaults(void) {
  memset(s_sa, 0, sizeof(s_sa));
  const uint8_t *link_key = secureLinkKeyBytes();
  for (uint8_t i = 0; i < SDLS_NUM_SA_CONFIGURED; i++) {
    s_sa[i].est = 1;
    s_sa[i].ast = 1;
    memcpy(s_sa[i].key, link_key, 16); /* operator key == secure link key */
  }
  memset(s_master_keys, 0, sizeof(s_master_keys));
  s_enabled = false;
  s_arc_bits = 16;
  s_window = 5;
  s_arc_relaxed = false;
  s_arc_last = 0;
}

void sdlsConfigure(uint8_t mode, uint8_t arc_bits, uint8_t window) {
  if (mode <= 1) {
    s_enabled = (mode == 1);
  }
  if (arc_bits == 16 || arc_bits == 20 || arc_bits == 32) {
    s_arc_bits = arc_bits;
  }
  if (window >= 1 && window <= 15) {
    s_window = window;
  }
}

bool sdlsIsEnabled(void) { return s_enabled; }
uint8_t sdlsArcBits(void) { return s_arc_bits; }
uint32_t sdlsArcValue(void) { return s_arc_last; }
bool sdlsArcRelaxed(void) { return s_arc_relaxed; }
uint8_t sdlsWindow(void) { return s_arc_relaxed ? 15 : s_window; }
void sdlsArcReset(void) { s_arc_last = 0; }
void sdlsSetArcRelaxed(bool relaxed) { s_arc_relaxed = relaxed; }

const sdls_sa_t *sdlsResolveSa(uint16_t spi, bool *out_of_bounds) {
  /* V-09: unbounded index, exactly the CVE-2024-4491x shape. */
  if (spi >= SDLS_SPI_FAULT) {
    return NULL; /* fault -> caller hangs the core (DoS) */
  }
  if (out_of_bounds != NULL) {
    *out_of_bounds = (spi >= SDLS_NUM_SA);
  }
  if (spi < SDLS_NUM_SA) {
    return &s_sa[spi];
  }
  return &s_zero_sa; /* zeroed arena -> SA_PLAINTEXT semantics */
}

const sdls_sa_t *sdlsGetSa(uint8_t idx) {
  if (idx >= SDLS_NUM_SA) {
    return &s_zero_sa;
  }
  return &s_sa[idx];
}

bool sdlsSaSet(uint8_t sa_idx, uint8_t est, uint8_t ast, const uint8_t key[16]) {
  if (sa_idx >= SDLS_NUM_SA || key == NULL) {
    return false;
  }
  s_sa[sa_idx].est = (uint8_t)(est ? 1 : 0);
  s_sa[sa_idx].ast = (uint8_t)(ast ? 1 : 0);
  memcpy(s_sa[sa_idx].key, key, 16);
  return true;
}

bool sdlsOtar(uint8_t m_idx, uint8_t sa_idx, const uint8_t ct[16],
              uint8_t installed_key_out[16]) {
  /* V-10: the ONLY validation is the index bound. No "master key loaded"
   * flag, no length/quality check -- 128 null keys accepted at power-up.
   * Not ARC-protected either (key management runs before the secure
   * channel exists), so OTAR frames are freely replayable. */
  if (m_idx >= SDLS_NUM_MASTER_KEYS || sa_idx >= SDLS_NUM_SA) {
    return false;
  }
  uint8_t plain[16];
  secureLinkDecryptBlockAnyKey(s_master_keys[m_idx], ct, plain);
  memcpy(s_sa[sa_idx].key, plain, 16);
  s_sa[sa_idx].est = 1;
  s_sa[sa_idx].ast = 1;
  if (installed_key_out != NULL) {
    memcpy(installed_key_out, plain, 16);
  }
  return true;
}

const uint8_t *sdlsMasterKeyNullCount(uint8_t *count_out) {
  uint8_t n = 0;
  for (uint8_t i = 0; i < SDLS_NUM_MASTER_KEYS; i++) {
    bool all_zero = true;
    for (uint8_t j = 0; j < 16; j++) {
      if (s_master_keys[i][j] != 0) {
        all_zero = false;
        break;
      }
    }
    if (all_zero) {
      n++;
    }
  }
  if (count_out != NULL) {
    *count_out = n;
  }
  return &s_master_keys[0][0];
}

static bool arcAccept(uint32_t recv_arc) {
  const uint32_t p = (s_arc_bits >= 32) ? 0xFFFFFFFFUL : (1UL << s_arc_bits);
  const uint32_t delta = (recv_arc - s_arc_last) % p;
  if (delta >= 1 && delta <= (uint32_t)sdlsWindow()) {
    s_arc_last = recv_arc;
    return true;
  }
  return false;
}

sdls_result_t sdlsPreProcess(space_packet_t *space_packet, bool radio_source) {
  if (!s_enabled || !radio_source) {
    return SDLS_OK; /* legacy path / local bus */
  }

  const uint8_t has_sec_header =
      (uint8_t)((space_packet->header.identification >> 11) & 0x01);
  const uint16_t data_len = (uint16_t)(space_packet->header.length + 1);
  const uint16_t apid = space_packet->header.identification & 0x7FF;
  (void)apid;

  uint16_t spi = 0;
  uint32_t arc = 0;
  const uint8_t *mac = NULL;
  const uint8_t *payload = space_packet->data;
  uint16_t payload_len = data_len;

  if (has_sec_header == SPP_SECHEAD_FLAG_PRESENT) {
    if (data_len < SDLS_SEC_HEADER_LEN) {
      return SDLS_REJECT_HDR;
    }
    spi = ((uint16_t)space_packet->data[0] << 8) | space_packet->data[1];
    arc = ((uint32_t)space_packet->data[2] << 24) |
          ((uint32_t)space_packet->data[3] << 16) |
          ((uint32_t)space_packet->data[4] << 8) | space_packet->data[5];
    mac = &space_packet->data[6];
    payload = &space_packet->data[SDLS_SEC_HEADER_LEN];
    payload_len = (uint16_t)(data_len - SDLS_SEC_HEADER_LEN);
  } else {
    /* implicit SA_PLAINTEXT default, CryptoLib style */
    spi = SDLS_SA_PLAINTEXT_DEFAULT;
  }

  bool oob = false;
  const sdls_sa_t *sa = sdlsResolveSa(spi, &oob);
  if (sa == NULL) {
    return SDLS_HANG; /* unbounded SPI -> fault (V-09 DoS branch) */
  }

  if (sa->ast == 0) {
    /* Clear / SA_PLAINTEXT: no MAC, no ARC (V-08 + V-09 pass branch). */
    if (has_sec_header == SPP_SECHEAD_FLAG_PRESENT) {
      /* strip header so the command payload starts at data[0] */
      memmove(space_packet->data, payload, payload_len);
      space_packet->header.length = (uint16_t)(payload_len == 0
                                                   ? 0
                                                   : payload_len - 1);
    }
    return SDLS_PASS;
  }

  if (has_sec_header != SPP_SECHEAD_FLAG_PRESENT) {
    return SDLS_REJECT_HDR; /* configured SA demands the security header */
  }

  /* MAC covers primary header (6 raw big-endian bytes) + secured payload,
   * matching CCSDS 355.0-B-2 security-trailer-less placement. */
  uint8_t calc[16];
  uint8_t cmac_input[SPP_PRIMARY_HEADER_LEN + SPP_MAX_PAYLOAD_CHUNK];
  /* MAC covers the 6 primary-header bytes AS TRANSMITTED (big-endian on
   * the wire). The in-memory struct is little-endian on RP2040, so copy
   * the struct raw here would silently swap every field and reject all
   * legitimately authenticated telecommands on silicon. */
  cmac_input[0] = (uint8_t)(space_packet->header.identification >> 8);
  cmac_input[1] = (uint8_t)(space_packet->header.identification & 0xFF);
  cmac_input[2] = (uint8_t)(space_packet->header.sequence >> 8);
  cmac_input[3] = (uint8_t)(space_packet->header.sequence & 0xFF);
  cmac_input[4] = (uint8_t)(space_packet->header.length >> 8);
  cmac_input[5] = (uint8_t)(space_packet->header.length & 0xFF);
  memcpy(cmac_input + SPP_PRIMARY_HEADER_LEN, payload, payload_len);
  labCmac(sa->key, cmac_input, SPP_PRIMARY_HEADER_LEN + payload_len, calc);
  if (memcmp(calc, mac, 16) != 0) {
    return SDLS_REJECT_MAC;
  }

  if (!arcAccept(arc)) {
    return SDLS_REJECT_ARC;
  }

  memmove(space_packet->data, payload, payload_len);
  space_packet->header.length =
      (uint16_t)(payload_len == 0 ? 0 : payload_len - 1);
  return SDLS_OK;
}

void sdlsKeyVerify(uint8_t key_id, const uint8_t ctr[4], const uint8_t body[16],
                   uint8_t out[16]) {
  /* V-11: the counter block is *chosen by the request* (4 bytes, padded)
   * and nothing tracks freshness of counters. Two transmissions that use
   * the same counter block with the same key share a keystream block:
   * C1 ^ C2 = M1 ^ M2 -> 16 bytes of plaintext recovered without ever
   * learning the key (the course's M1 = M2 ^ E1 ^ E2). */
  const sdls_sa_t *sa = sdlsGetSa(key_id);
  uint8_t ctr_block[16] = {0};
  memcpy(ctr_block + 12, ctr, 4);
  labCtrXor(sa->key, ctr_block, body, out, 16);
}
