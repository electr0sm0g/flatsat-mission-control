/*  - covert.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "covert.h"
#include "memserv.h"
#include <string.h>

static uint8_t s_mode = 0;
static uint8_t s_queue[COVERT_QUEUE_SIZE];
static uint16_t s_head = 0; /* dequeue position */
static uint16_t s_tail = 0; /* enqueue position */
static uint16_t s_depth = 0;
static uint16_t s_vcc = 0; /* virtual capture counter (V-31 audit) */
static bool s_vcc_frozen = false;

uint8_t covertPaddingMode(void) { return s_mode; }

void covertSetPaddingMode(uint8_t mode) {
  if (mode <= 2) {
    s_mode = mode;
  }
}

bool covertEnqueue(const uint8_t *data, uint16_t len) {
  if (len > COVERT_QUEUE_SIZE - s_depth) {
    return false; /* fail closed: never silently corrupt the FIFO */
  }
  for (uint16_t i = 0; i < len; i++) {
    s_queue[s_tail] = data[i];
    s_tail = (uint16_t)((s_tail + 1) % COVERT_QUEUE_SIZE);
  }
  s_depth = (uint16_t)(s_depth + len);
  return true;
}

uint16_t covertQueueDepth(void) { return s_depth; }

uint16_t covertDequeue(uint8_t *out, uint16_t max_len) {
  uint16_t n = (s_depth < max_len) ? s_depth : max_len;
  for (uint16_t i = 0; i < n; i++) {
    out[i] = s_queue[s_head];
    s_head = (uint16_t)((s_head + 1) % COVERT_QUEUE_SIZE);
  }
  s_depth = (uint16_t)(s_depth - n);
  return n;
}

void covertApplyPadding(uint8_t *out, uint16_t pay_len, uint16_t pad_to) {
  if (pad_to <= pay_len) {
    return;
  }
  const uint16_t need = (uint16_t)(pad_to - pay_len);
  if (s_mode == 2) {
    const uint16_t got = covertDequeue(out + pay_len, need);
    if (got < need) {
      memset(out + pay_len + got, 0, need - got);
    }
    return;
  }
  if (s_mode == 1) {
    labLeakTake(out + pay_len, need);
    return;
  }
  memset(out + pay_len, 0, need);
}

uint16_t covertVcc(void) { return s_vcc; }
bool covertVccFrozen(void) { return s_vcc_frozen; }
void covertVccFreeze(bool freeze) { s_vcc_frozen = freeze; }
void covertVccBump(void) {
  if (!s_vcc_frozen) {
    s_vcc++;
  }
}
/* V-31/V-32 bench parity: the reference model keeps ONE forward counter
 * (self.vcc) bumped by BOTH broadcast (ungated) and snap (freeze-gated).
 * The broadcast path uses this ungated bump so 0x0C/0x0F (which expose
 * covertVcc()) reflect relayed payloads exactly like the simulator. */
void covertVccBumpUnconditional(void) { s_vcc++; }
