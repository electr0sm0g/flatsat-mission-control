/*  - covert.h
 *
 * flatsat-lab vulnerable firmware v2 -- TM padding policy + covert queue
 * (course ch.10.2 hidden-channel/stego exfiltration + ch.2.1 Heartbleed
 * style RAM leak).
 *
 *   mode 0: padding = zeros (the boring, correct default)
 *   mode 1: padding = raw uninitialised RAM residue (V-04 leak channel)
 *   mode 2: padding = bytes drained from the covert FIFO (V-30 exfil)
 *
 * Beams are padded to a fixed 64-byte payload so every beacon carries a
 * deterministic number of covert bytes -- the "audit looks like valid
 * housekeeping" property from the course.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_COVERT_H
#define FIRMWARE_COVERT_H
#include <Arduino.h>

#define COVERT_PAD_TARGET 64
#define COVERT_QUEUE_SIZE 1024

uint8_t covertPaddingMode(void);
void covertSetPaddingMode(uint8_t mode); /* 0 zeros, 1 RAM leak, 2 FIFO */
bool covertEnqueue(const uint8_t *data, uint16_t len); /* APID 0x22 */
uint16_t covertQueueDepth(void);
uint16_t covertDequeue(uint8_t *out, uint16_t max_len); /* drain for TM pad */
/* Fill `out[pay_len..pad_to)` according to the current padding policy. */
void covertApplyPadding(uint8_t *out, uint16_t pay_len, uint16_t pad_to);
/* audit counters */
uint16_t covertVcc(void); /* payload-visit counter mirror (V-31) */
bool covertVccFrozen(void);
void covertVccFreeze(bool freeze);
void covertVccBump(void);
void covertVccBumpUnconditional(void); /* broadcast path: no freeze gate */

#endif // FIRMWARE_COVERT_H
