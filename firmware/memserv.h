/*  - memserv.h
 *
 * flatsat-lab vulnerable firmware v2 -- in-band memory service.
 *
 * The TC-defined memcpy()/read primitives mirror the Flying Laptop and
 * ESTCube-1 "TC memcpy" telecommands (course ch.2.1 / ch.7.1): the packet
 * carries source, destination and length, so an attacker holding only
 * unauthenticated uplink gains an arbitrary 16-bit read/write primitive
 * over the whole RP2040 address map. On Cortex-M0+ the vector-table offset
 * register SCB->VTOR (0xE000ED08, PPB) is writable at any privilege level
 * and cannot be locked -- redirecting it into SRAM and letting the next
 * interrupt fire is a real, silicon-supported RCE on this board.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_MEMSERV_H
#define FIRMWARE_MEMSERV_H
#include <Arduino.h>

/* APID 0x19: copy out len bytes starting at addr (max 200, one TM). */
bool memservRead(uint32_t addr, uint16_t len, uint8_t *out);
/* APID 0x18: byte-by-byte copy src->dst (max 200). Returns false and
 * flags a fault (hang) on writes to unmapped regions. */
bool memservCopy(uint32_t src, uint32_t dst, uint16_t len);
/* VTOR effect check after a copy touched 0xE000ED08 (see labhooks). */
bool memservVtorCheckFired(void);

/* APID 0x1A: V-13, unbounded strcpy into log_name[32]. The global layout
 * is deliberately arranged so the adjacent bytes are usbDebugEnabled and
 * the secure-link enable -- see memserv.c for the attribute ordering. */
void memservSetLogName(const char *name);
const char *memservGetLogName(void);

/* Raw-RAM "Heartbleed" leak pool (V-04): bytes that past crypto/GS
 * operations left in uninitialised TM padding regions. */
void labLeakWrite(const uint8_t *bytes, size_t len); /* models stack residue */
void labLeakTake(uint8_t *out, size_t len);          /* read from the pool */

#endif // FIRMWARE_MEMSERV_H
