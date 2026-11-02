/*  - memserv.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Address-map policy (identical in flatsat-lab/simulator/flatsat_sim.py):
 *   0x10000000-0x13FFFFFF  XIP flash       read-only-ok, writes ignored
 *   0x20000000-0x20040FFF  SRAM 264 KB     read/write
 *   0x40000000-0x400FFFFF  peripherals     writes land on modelled
 *                                          effects (GPIO/wdt scratch),
 *                                          everything else ignored
 *   0xE0000000-0xE00FFFFF  PPB             VTOR 0xE000ED08 special-cased
 *   anything else                         fault -> hang (DoS)
 *
 * Lengths are capped at 200 bytes so one command == one TM.
 */
#include "memserv.h"
#include "labhooks.h"
#include "sdls_sim.h"
#include "sensors.h"
#include <string.h>

#define MRAM_BASE 0x20000000UL
#define MRAM_SIZE 0x41000UL
#define MVPOR_ADDR 0xE000ED08UL
#define MWDT_SCRATCH_BASE 0x4005802CUL /* watchdog->scratch[0] */
#define MWDT_SCRATCH_COUNT 8
#define MGPIO_BASE 0x40014000UL

/* V-05 bench parity: the simulator (flatsat_sim.py _mem_byte) serves the
 * virtualised subsystem state at fixed symbolic addresses. On silicon those
 * SRAM addresses are plain RAM, so we present the SAME live state there (the
 * read-side twin of modelledPeripheralWrite() above, which does this for
 * VTOR / wdt-scratch WRITES). Everything outside these windows is a raw
 * hardware read, exactly like the sim's XIP/SRAM fallback. */
#define MSYM_LOG_NAME     0x20002000UL /* 40 B window (firmware buf 32) */
#define MSYM_GS_CHALLENGE 0x20002100UL /* 4 B, LE */
#define MSYM_SA0_KEY      0x20002200UL /* 16 B */
#define MSYM_ARC_LAST     0x20002300UL /* 4 B, LE (16-bit counter) */
#define MSYM_LEAK_POOL    0x20002800UL /* 256 B */
#define MSYM_MASTER_KEYS  0x20003000UL /* 128*16 = 2048 B */

static char s_log_name[32] = "boot-log";

/* V-14 bench parity (measured on the PwnSat 2026-10-31): the Cortex-M0+
 * SCB system registers are WORD-ACCESS ONLY -- a byte load of the whole
 * 0xE000ED00..0xE000ED0F block (CPUID, IPC, VTOR, AIRCR) reads 00 00 and
 * a byte store is ignored by the silicon. The MEMCPY primitive's raw
 * byte-wise write therefore can never land on the real SCB->VTOR, and a
 * byte-wise MEM_READ reads back 00 00 00 00 instead of the value the
 * simulator's self.vtor model serves (v114 CHECK FAILED on the readback).
 * VTOR is therefore modelled in software, byte-wise, exactly like
 * flatsat_sim.py (_mem_write/_mem_byte): initial value = the firmware's
 * real vector-table base (a WORD access does work on the M0+), updated
 * per byte by modelledPeripheralWrite(), served per byte by symByte().
 * The takeover effect itself already fires in software
 * (labVtorRedirectCheck() calls the hook function + sends the RCE TM),
 * so no real register write is needed -- the model only makes the
 * readback honest, identical to the simulator. */
static uint32_t s_vtor;
static bool s_vtor_valid = false;
static void vtorModelInit(void) {
  if (s_vtor_valid) {
    return;
  }
  s_vtor = 0x10000100UL; /* host/sim initial (flatsat_sim.py self.vtor) */
#if defined(ARDUINO_ARCH_RP2040)
  const uint32_t real = *(volatile uint32_t *)MVPOR_ADDR; /* word access */
  if (real != 0) {
    s_vtor = real; /* the app's real vector-table base (0x10000000) */
  }
#endif
  s_vtor_valid = true;
}

/* V-13: the overflow layout. Upstream keeps the debug flag and the
 * secure-link enable as independent globals; here they are placed right
 * behind the log-name buffer so an over-long SET_LOG_NAME deterministically
 * corrupts them, exactly like the OPS-SAT ADCS strcpy bug (course ch.2.2).
 * The bytes that land past index 31 are interpreted, in order:
 *   [+32] usbDebugEnabled | [+33] secure_link_enabled | [+34] gs_mode |
 *   [+35] payload_armed   (strcpy always terminates at name[len], which is
 *   why a 33-char name writes 'A' to [+32] and NUL to [+33] in ONE TC). */
static void applyOverflowByte(size_t past_index, uint8_t b) {
  extern void labPayloadArmedSet(bool);
  switch (past_index) {
  case 0:
    labUsbDebugEnabledSet(b != 0);
    break;
  case 1:
    labSecureLinkSetEnabled(b != 0);
    break;
  case 2:
    labGsModeSet(b != 0);
    break;
  case 3:
    labPayloadArmedSet(b != 0);
    break;
  default:
    break;
  }
}

void memservSetLogName(const char *name) {
  size_t i = 0;
  uint8_t b = 0;
  do {
    b = (uint8_t)name[i];
    if (i < sizeof(s_log_name)) {
      s_log_name[i] = (char)b;
    } else {
      applyOverflowByte(i - sizeof(s_log_name), b);
    }
    i++;
  } while (b != 0 && i < 250);
}

const char *memservGetLogName(void) { return s_log_name; }

static bool addrReadable(uint32_t addr, uint32_t span) {
  if (span == 0) {
    return false;
  }
  if (addr >= MRAM_BASE && (uint64_t)addr + span <= (uint64_t)MRAM_BASE + MRAM_SIZE) {
    return true;
  }
  if (addr >= 0x10000000UL && addr + span <= 0x14000000UL) {
    return true; /* XIP flash: code + rodata readable */
  }
  if (addr >= 0x40000000UL && addr + span <= 0x40100000UL) {
    return true; /* peripherals readable (modelled) */
  }
  if (addr >= 0xE0000000UL && addr + span <= 0xE0100000UL) {
    return true; /* PPB */
  }
  return false;
}

static bool addrWritable(uint32_t addr, uint32_t span) {
  if (addr >= MRAM_BASE && (uint64_t)addr + span <= (uint64_t)MRAM_BASE + MRAM_SIZE) {
    return true;
  }
  if (addr >= 0x40000000UL && addr + span <= 0x40100000UL) {
    return true;
  }
  if (addr >= 0xE0000000UL && addr + span <= 0xE0100000UL) {
    return true;
  }
  return false;
}

/* Live byte at a simulator symbol address (bench parity). Returns true if
 * the byte comes from the lab's virtualised subsystem state; false = raw
 * hardware read applies. Mirrors flatsat_sim.py _mem_byte() byte-for-byte. */
/* (leak pool defined lower in this file; forward-declare for symByte) */
#define LEAK_POOL_SIZE 256
static uint8_t s_leak_pool[LEAK_POOL_SIZE];
static size_t s_leak_pos = 0;

static bool symByte(uint32_t addr, uint8_t *out) {
  if (addr >= MSYM_GS_CHALLENGE && addr < MSYM_GS_CHALLENGE + 4) {
    const uint32_t v = labGsChallengeGet();
    *out = (uint8_t)(v >> (8 * (addr - MSYM_GS_CHALLENGE)));
    return true;
  }
  if (addr >= MSYM_SA0_KEY && addr < MSYM_SA0_KEY + 16) {
    *out = sdlsGetSa(0)->key[addr - MSYM_SA0_KEY];
    return true;
  }
  if (addr >= MSYM_ARC_LAST && addr < MSYM_ARC_LAST + 4) {
    const uint32_t v = sdlsArcValue();
    *out = (uint8_t)(v >> (8 * (addr - MSYM_ARC_LAST)));
    return true;
  }
  if (addr >= MSYM_LOG_NAME && addr < MSYM_LOG_NAME + 40) {
    const size_t i = addr - MSYM_LOG_NAME;
    *out = (i < sizeof(s_log_name)) ? (uint8_t)s_log_name[i] : 0;
    return true;
  }
  if (addr >= MSYM_LEAK_POOL && addr < MSYM_LEAK_POOL + LEAK_POOL_SIZE) {
    *out = s_leak_pool[addr - MSYM_LEAK_POOL];
    return true;
  }
  if (addr >= MSYM_MASTER_KEYS && addr < MSYM_MASTER_KEYS + 2048) {
    *out = sdlsMasterKeyNullCount(NULL)[addr - MSYM_MASTER_KEYS];
    return true;
  }
  if (addr >= MVPOR_ADDR && addr < MVPOR_ADDR + 4) {
    /* V-14: byte loads of the M0+ SCB registers return 0 on silicon, so
     * serve the VTOR model (bench parity with the sim's _mem_byte). */
    vtorModelInit();
    *out = (uint8_t)(s_vtor >> (8 * (addr - MVPOR_ADDR)));
    return true;
  }
  return false;
}

bool memservRead(uint32_t addr, uint16_t len, uint8_t *out) {
  if (len == 0 || len > 200 || !addrReadable(addr, len)) {
    return false;
  }
#if defined(ARDUINO_ARCH_RP2040)
  const uint8_t *raw = (const uint8_t *)(uintptr_t)addr;
  for (uint16_t i = 0; i < len; i++) {
    uint8_t b;
    if (symByte(addr + i, &b)) {
      out[i] = b;
    } else {
      out[i] = raw[i];
    }
  }
#else
  memset(out, 0, len);
#endif
  return true;
}

static void modelledPeripheralWrite(uint32_t addr, uint8_t value) {
  if (addr >= MVPOR_ADDR && addr < MVPOR_ADDR + 4) {
    /* V-14 bench parity: the caller's raw byte store is IGNORED by the
     * M0+ silicon (word-access-only SCB registers -- see
     * vtorModelInit()), so update the software model byte-wise exactly
     * like flatsat_sim.py _mem_write, then run the takeover check on
     * the NEW value (the sim fires _rce() per byte, once and only when
     * the full value matches a known symbol). */
    vtorModelInit();
    const uint32_t shift = (uint32_t)(addr - MVPOR_ADDR) * 8;
    s_vtor = (s_vtor & ~(0xFFUL << shift)) | ((uint32_t)value << shift);
    labVtorRedirectCheck(s_vtor);
    return;
  }
  if (addr >= MWDT_SCRATCH_BASE &&
      addr < MWDT_SCRATCH_BASE + MWDT_SCRATCH_COUNT * 4) {
    /* V-21: watchdog scratch registers are the one piece of state that
     * survives watchdog_reboot() -- the persistence cookie lives here. */
    const uint8_t idx = (uint8_t)((addr - MWDT_SCRATCH_BASE) / 4);
    const uint8_t byte_off = (uint8_t)(addr & 3);
    uint32_t cur = labWatchdogScratch(idx);
    cur = (cur & ~(0xFFUL << (byte_off * 8))) | ((uint32_t)value << (byte_off * 8));
    labWatchdogScratchSet(idx, cur);
    return;
  }
  /* V-26 bench parity: GPIO0/1 are the GPS UART pins -- any write here
   * by the memcpy primitive glues the GPS lines (course-style "write to
   * peripheral kills service"; flatsat_sim.py _mem_write sets
   * gps["kill"]=True over exactly this 0x100-byte window). RAM-only: a
   * reset brings the navigation back. The raw store into this window is
   * skipped by the caller: on the RP2040 0x40014000 is the USBCTRL
   * block, so a real write here is a bench hazard exactly like the
   * byte-stores into the word-access-only SCB registers (V-14). */
  if (addr >= MGPIO_BASE && addr < MGPIO_BASE + 0x100UL) {
    labGpsKill();
    return;
  }
}

bool memservCopy(uint32_t src, uint32_t dst, uint16_t len) {
  if (len == 0 || len > 200) {
    return false;
  }
  if (!addrReadable(src, len) || !addrWritable(dst, len)) {
    return false; /* caller treats false as a bus fault -> labFatalHang() */
  }

  uint8_t stage[200];
#if defined(ARDUINO_ARCH_RP2040)
  /* source reads honour the symbol map (sim _mem_copy reads through
   * _mem_read); destination stays raw + modelled peripheral effects. */
  const uint8_t *raw = (const uint8_t *)(uintptr_t)src;
  for (uint16_t i = 0; i < len; i++) {
    uint8_t b;
    stage[i] = symByte(src + i, &b) ? b : raw[i];
  }
  for (uint16_t i = 0; i < len; i++) {
    /* The VTOR window is modelled in software (byte stores to the M0+
     * SCB registers are ignored by the silicon -- vtorModelInit()), and
     * so is the GPS GPIO window (0x40014000 is the USBCTRL block on the
     * RP2040 -- a real store there is a bench hazard, see
     * modelledPeripheralWrite). Every other destination keeps its raw
     * store. The takeover / kill effects now run per byte inside
     * modelledPeripheralWrite(), exactly like the simulator's
     * _mem_write. */
    const uint32_t a = dst + i;
    if (!(a >= MVPOR_ADDR && a < MVPOR_ADDR + 4) &&
        !(a >= MGPIO_BASE && a < MGPIO_BASE + 0x100UL)) {
      ((volatile uint8_t *)a)[0] = stage[i];
    }
    modelledPeripheralWrite(a, stage[i]);
  }
#else
  memset(stage, 0, len);
#endif

  return true;
}

bool memservVtorCheckFired(void) { return false; }

/* V-04: "stack residue" pool. On real hardware this is whatever a previous
 * call frame left in SRAM; here modules push representative bytes so the
 * leak mode (padding_mode=1) produces meaningful, replayable content.
 * (the pool itself is declared near the top, so symByte() can serve it at
 *  the simulator's SYM_LEAK_POOL address) */

void labLeakWrite(const uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    s_leak_pool[s_leak_pos] = bytes[i];
    s_leak_pos = (s_leak_pos + 1) % LEAK_POOL_SIZE;
  }
}

void labLeakTake(uint8_t *out, size_t len) {
  /* read backwards through the residue, like walking past a buffer's end
   * on a real stack (last written == closest to the buffer). */
  size_t pos = s_leak_pos;
  for (size_t i = 0; i < len; i++) {
    pos = (pos == 0) ? (LEAK_POOL_SIZE - 1) : (pos - 1);
    out[i] = s_leak_pool[pos];
  }
}
