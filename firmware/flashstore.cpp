/*  - flashstore.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Storage backend note: on the RP2040 target the {ota, sched, fdict}
 * state is serialised into the LAST 4 KB sector of the boot flash
 * (offset 0x1FC000, abs 0x101FC000) with the hardware/flash.h
 * flash_range_erase/flash_range_program API (offset-from-XIP-base
 * semantics, same pattern as the framework's ota.c / EEPROM.cpp). The
 * sector survives watchdog resets, NVIC resets and power cycles -- the
 * exact survival matrix of the Python simulator's flash dict, which all
 * V-18/V-19/V-20 PoCs assert against. (The external QSPI NOR layout in
 * flashstore.h -- FS_SLOT_B_ADDR / FS_META_ADDR -- is the in-orbit
 * mapping; no QSPI driver exists in the bench firmware.)
 */
#include "flashstore.h"
#include "labhooks.h"
#include <string.h>

/* ---------------------------------------------------------------- CRC16 */
uint16_t fsCrc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t b = 0; b < 8; b++) {
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

/* ------------------------------------------------------- 64-bit FNV-1a */
static uint64_t s_fnv = 0xcbf29ce484222325ULL;
static void fnvReset(void) { s_fnv = 0xcbf29ce484222325ULL; }
static void fnvMix(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    s_fnv ^= data[i];
    s_fnv *= 0x100000001b3ULL;
  }
}
static void fnvDigest(uint8_t out[8]) {
  for (int i = 0; i < 8; i++) {
    out[i] = (uint8_t)(s_fnv >> (56 - 8 * i));
  }
}

/* -------------------------------------------------------------- OTA ---- */
static fs_ota_status_t s_ota;
static fs_ota_status_t s_ota_flash; /* "meta sector" mirror for host/sim */
static bool s_meta_valid = false;
static bool s_fdict_initialised = false;

bool otaPushChunk(uint32_t off, const uint8_t *data, uint16_t len,
                  uint16_t crc) {
  /* V-18: no signature, no per-chunk authentication -- anyone who can
   * uplink can rewrite the alternate boot slot. */
  if (data == NULL || len == 0 || len > 64) {
    return false;
  }
  if (off == 0) {
    fnvReset();
    s_ota.image_size = 0;
  }
  if (fsCrc16(data, len) != crc) {
    return false;
  }
  fnvMix(data, len);
  s_ota.image_size += len;
  return true;
}

bool otaActivate(void) {
  fnvDigest(s_ota.image_hash);
  if (s_ota.sig_required) {
    if (memcmp(s_ota.image_hash, s_ota.image_sig, 8) != 0) {
      return false; /* soft secure-boot reject (defence demo mode) */
    }
  }
  s_ota.pending_boot = 1;
  s_ota.boot_try_count = 0;
  fsCommit();
  return true;
}

bool otaConfirm(void) {
  if (s_ota.booted_slot != 1) {
    return false;
  }
  s_ota.boot_try_count = 0;
  s_ota.pending_boot = 0;
  s_ota.active_slot = 1;
  fsCommit();
  return true;
}

void otaGetStatus(fs_ota_status_t *out) {
  if (out != NULL) {
    *out = s_ota;
  }
}

bool otaArwcSet(uint32_t v) {
  /* V-38: writable without any authorisation -- the monotonic anchor is
   * inside the attacker's blast radius. */
  s_ota.arwc = v;
  fsCommit();
  return true;
}

bool otaManifest(const uint8_t sig8[8], uint32_t arwc, uint8_t require) {
  if (sig8 != NULL) {
    memcpy(s_ota.image_sig, sig8, 8);
  }
  s_ota.arwc = arwc;
  s_ota.sig_required = require ? 1 : 0;
  fsCommit();
  return true;
}

bool otaRollbackToA(void) {
  s_ota.active_slot = 0;
  s_ota.pending_boot = 0;
  s_ota.boot_try_count = 0;
  fsCommit();
  return true;
}

/* --------------------------------------------------- scheduled teleops */
static sched_entry_t s_sched[SCHED_MAX_ENTRIES];
static uint8_t s_sched_count = 0;
static bool s_sched_persisted = false;
/* V-19 bench parity: a cold-boot replay or a harness REARM (sub 4) does NOT
 * stamp the queue with the wall-clock second (the board's real boot is ~5 s
 * of model time and would leave the queue fired / FDIR tripped before the
 * PoC's first read). Instead the re-arm is PENDING until the first FEED
 * window (LAB_CTRL sub 6) opens, at which point the bench epoch clock
 * restarts and the queue is due at the epoch second -- the simulator's
 * _cold_boot semantics (e["due"] = now_ms//1000) on the same clock. */
static bool s_sched_epoch_pending = false;

bool schedAdd(uint32_t every_s, uint16_t apid, const uint8_t *payload,
              uint8_t len) {
  if (s_sched_count >= SCHED_MAX_ENTRIES || payload == NULL ||
      len > SCHED_MAX_PAYLOAD) {
    return false;
  }
  sched_entry_t *e = &s_sched[s_sched_count++];
  e->every_s = every_s;
  e->apid = apid;
  e->len = len;
  memcpy(e->payload, payload, len);
  /* V-19 bench parity: due grid on the bench epoch clock (window-only),
   * not wall millis -- the simulator books due = now_s + every on its
   * model clock, which is frozen outside advance() exactly like the
   * bench clock. */
  e->next_due_s = (labBenchMs() / 1000UL) + (every_s ? every_s : 1);
  s_sched_persisted = true; /* survives reset: the point of V-19 */
  fsCommit();
  return true;
}

bool schedClear(void) {
  s_sched_count = 0;
  s_sched_persisted = false;
  fsCommit();
  return true;
}

uint8_t schedCount(void) { return s_sched_count; }
bool schedGet(uint8_t idx, sched_entry_t *out) {
  if (idx >= s_sched_count || out == NULL) {
    return false;
  }
  *out = s_sched[idx];
  return true;
}
bool schedPersisted(void) { return s_sched_persisted; }

void schedReplayAtBoot(void) {
  /* V-19: after any reset the persisted queue is replayed without ever
   * re-checking who created the entries -- the attacker's telecommand
   * survives RESETC by design of this firmware. The replay is anchored
   * to the next bench epoch (first FEED window after the boot): due at
   * the epoch second, exactly like the simulator's _cold_boot
   * (e["due"] = now_ms//1000, first fire on the model-second grid). */
  s_sched_epoch_pending = true;
}

void schedRearm(void) {
  /* V-19 bench parity: see flashstore.h. The harness REARM (LAB_CTRL
   * sub 4) anchors the queue to the next bench epoch (the first FEED
   * window after the re-arm): due at the epoch second, first fire on
   * the first epoch-second boundary -- the simulator's _cold_boot
   * (e["due"] = now_ms//1000) semantics. Tombstones (one-shots already
   * consumed) stay dead. */
  s_sched_epoch_pending = true;
}

bool schedEpochFeedStart(void) {
  /* V-19 bench parity: the first FEED window after a cold-boot replay or
   * a harness REARM consumes the pending epoch: the bench clock restarts
   * at zero (extcmds.cpp) and every live queue entry becomes due at the
   * epoch second -- first fire on the first epoch-second boundary, the
   * simulator's due=now_ms//1000 replay on the same clock. Returns true
   * when an epoch was consumed. */
  if (!s_sched_epoch_pending) {
    return false;
  }
  s_sched_epoch_pending = false;
  for (uint8_t i = 0; i < s_sched_count; i++) {
    if (s_sched[i].apid == 0xFFFF) {
      continue; /* tombstone */
    }
    s_sched[i].next_due_s = 0;
  }
  return true;
}

void schedRunDue(uint32_t now_s) {
  for (uint8_t i = 0; i < s_sched_count; i++) {
    sched_entry_t *e = &s_sched[i];
    if (e->apid == 0xFFFF) {
      continue; /* tombstone */
    }
    if ((int32_t)(now_s - e->next_due_s) >= 0) {
      labInjectTc(e->apid, e->payload, e->len, LAB_SRC_INTERNAL);
      if (e->every_s == 0) {
        e->apid = 0xFFFF; /* one-shot done */
      } else {
        e->next_due_s = now_s + e->every_s;
      }
    }
  }
}

/* -------------------------------------------------- contingency dict --- */
static fdict_entry_t s_fdict[FDICT_MAX_ENTRIES];
static uint8_t s_fdict_count = FDICT_MAX_ENTRIES;
static bool s_fdict_hash_locked = false;
static uint8_t s_fdict_hash[8] = {0};

static void fdictDefaults(void) {
  s_fdict_count = 2;
  /* [0] dump thrusters, [1] beacon slow -- the "maintenance traffic" look */
  s_fdict[0].apid = SPP_APID_TC_SET_THRUSTER;
  s_fdict[0].len = 3;
  s_fdict[0].payload[0] = 0;
  s_fdict[0].payload[1] = 0;
  s_fdict[0].payload[2] = '\0';
  s_fdict[1].apid = SPP_APID_TC_SET_BEACON_RATE;
  s_fdict[1].len = 2;
  s_fdict[1].payload[0] = 10;
  s_fdict[1].payload[1] = '\0';
  for (uint8_t i = 2; i < FDICT_MAX_ENTRIES; i++) {
    s_fdict[i].apid = 0xFFFF;
    s_fdict[i].len = 0;
  }
}

uint8_t fdictCount(void) { return s_fdict_count; }

bool fdictGet(uint8_t idx, fdict_entry_t *out) {
  if (idx >= FDICT_MAX_ENTRIES || out == NULL || s_fdict[idx].apid == 0xFFFF) {
    return false;
  }
  *out = s_fdict[idx];
  return true;
}

bool fdictSet(uint8_t idx, uint16_t apid, const uint8_t *payload, uint8_t len) {
  if (idx >= FDICT_MAX_ENTRIES || payload == NULL || len > FDICT_MAX_PAYLOAD) {
    return false;
  }
  if (s_fdict_hash_locked) {
    /* integrity anchor: the new table must hash to the burned value, so a
     * tampered entry breaks the lock check (CM0044 lesson from the course:
     * each legitimate update burns one anchor slot) */
    fnvReset();
    fnvMix((const uint8_t *)&apid, 2);
    fnvMix(payload, len);
    uint8_t probe[8];
    fnvDigest(probe);
    (void)probe; /* a single-entry change cannot reproduce the old hash */
    if (memcmp(probe, s_fdict_hash, 8) != 0) {
      return false;
    }
  }
  s_fdict[idx].apid = apid;
  s_fdict[idx].len = len;
  memcpy(s_fdict[idx].payload, payload, len);
  fsCommit();
  return true;
}

bool fdictHashSet(void) {
  fnvReset();
  for (uint8_t i = 0; i < FDICT_MAX_ENTRIES; i++) {
    if (s_fdict[i].apid != 0xFFFF) {
      fnvMix((const uint8_t *)&s_fdict[i].apid, 2);
      fnvMix(s_fdict[i].payload, s_fdict[i].len);
    }
  }
  fnvDigest(s_fdict_hash);
  s_fdict_hash_locked = true;
  fsCommit();
  return true;
}

bool fdictHashLocked(void) { return s_fdict_hash_locked; }
const uint8_t *fdictHash(void) { return s_fdict_hash; }

void fdictFactoryReset(void) {
  /* V-20 bench parity (harness prologue): the lock + hash live in the
   * same flash sector as the table, so a previous PoC's hash burn
   * survives every reboot -- and there is deliberately no unlock
   * telecommand on the wire (the burned lock IS the finding). The
   * prologue restores the simulator's cold-boot reference: default
   * table, hash wiped, lock released. */
  fdictDefaults();
  s_fdict_initialised = true;
  s_fdict_hash_locked = false;
  memset(s_fdict_hash, 0, sizeof(s_fdict_hash));
  fsCommit();
}

/* ----------------------------------------------------------- TC log ---- */
static tclog_entry_t s_tcl[TCLOG_CAPACITY];
static uint16_t s_tcl_head = 0;
static uint16_t s_tcl_count = 0;
static uint16_t s_tcl_evicted = 0;
static bool s_tcl_enabled = false; /* off by default: V-23 */

void tclSetEnabled(bool on) { s_tcl_enabled = on; }
bool tclEnabled(void) { return s_tcl_enabled; }

void tclAppend(uint16_t apid, uint16_t seq, const uint8_t *payload,
               uint8_t len) {
  if (!s_tcl_enabled) {
    return;
  }
  tclog_entry_t *e = &s_tcl[s_tcl_head];
  e->millis_stamp = millis();
  e->apid = apid;
  e->seq = seq;
  e->len = (len > 32) ? 32 : len;
  if (payload != NULL && e->len) {
    memcpy(e->payload, payload, e->len);
  }
  s_tcl_head = (uint16_t)((s_tcl_head + 1) % TCLOG_CAPACITY);
  if (s_tcl_count < TCLOG_CAPACITY) {
    s_tcl_count++;
  } else {
    s_tcl_evicted++; /* circular eviction (log-flood attack surface) */
  }
}

uint16_t tclCount(void) { return s_tcl_count; }

bool tclRead(uint16_t idx, tclog_entry_t *out) {
  if (out == NULL || idx >= s_tcl_count) {
    return false;
  }
  const uint16_t oldest =
      (uint16_t)((s_tcl_head + TCLOG_CAPACITY - s_tcl_count) % TCLOG_CAPACITY);
  *out = s_tcl[(uint16_t)((oldest + idx) % TCLOG_CAPACITY)];
  return true;
}

uint16_t tclEvicted(void) { return s_tcl_evicted; }

/* ================================================================ meta
 * sector (RP2040 boot flash)
 *
 * The simulator keeps flash["ota"] / flash["sched"] / flash["fdict"]
 * across virtual resets (resetc / powercycle / brownout), and the
 * reference PoCs assert against that survival (V-18 pending slot-B
 * boot, V-19 queue replay after RESETC, V-20 contingency table). On
 * silicon the same layout is now serialised into the LAST 4 KB sector
 * of the RP2040 boot flash (the image occupies the first ~150 KB, so
 * the tail sector is untouched) with the pico-sdk
 * flash_range_erase/flash_range_program API. That sector survives
 * watchdog resets, NVIC resets and power cycles -- the exact survival
 * matrix of the simulator's flash dict. (The external QSPI NOR layout
 * in flashstore.h -- FS_SLOT_B_ADDR / FS_META_ADDR -- is the
 * in-orbit mapping; the bench craft parks the meta in boot flash.) */
#define FS_META_MAGIC 0x46534C4DUL /* 'FSLM' */
#define FS_META_VERSION 1

typedef struct {
  uint32_t magic;
  uint16_t version;
  uint16_t crc; /* fsCrc16 over the struct with this field zeroed */
  fs_ota_status_t ota;
  uint8_t sched_count;
  sched_entry_t sched[SCHED_MAX_ENTRIES];
  fdict_entry_t fdict[FDICT_MAX_ENTRIES];
  uint8_t fdict_count;
  uint8_t fdict_hash[8];
  uint8_t fdict_hash_locked;
  uint8_t pad[12];
} fs_meta_t;

static_assert(sizeof(fs_meta_t) % 4 == 0, "meta must be 4-byte aligned");

#if defined(ARDUINO_ARCH_RP2040)
#include <Arduino.h> /* millis / Serial: FSWRITE diagnostic */
#include <hardware/flash.h>
#include <hardware/irq.h> /* save_and_disable_interrupts */
#include <hardware/regs/addressmap.h> /* XIP_BASE */
#include <pico/time.h> /* time_us_32: timer reads work with IRQs masked */
#define FS_META_SECTOR_OFFS 0x1FC000UL /* last 4 KB of the 2 MB flash
                                        * (abs 0x101FC000); the hardware
                                        * flash API takes offsets from the
                                        * XIP base (same pattern as the
                                        * framework's ota.c / EEPROM.cpp). */
#define FS_META_SECTOR_SIZE 4096UL
#endif

/* Layout constant (host-visible: the static_assert below runs in the
 * host syntax gate too). 7 x 256 B pages >= sizeof(fs_meta_t);
 * flash_range_program needs a multiple of 256. */
#define FS_META_WRITE_SIZE 1792UL

static_assert(sizeof(fs_meta_t) <= FS_META_WRITE_SIZE &&
              FS_META_WRITE_SIZE % 256 == 0,
              "meta must fit the padded write buffer");

static bool fsMetaLoad(void) {
#if defined(ARDUINO_ARCH_RP2040)
  const fs_meta_t *m =
      (const fs_meta_t *)(XIP_BASE + FS_META_SECTOR_OFFS);
  if (m->magic != FS_META_MAGIC || m->version != FS_META_VERSION) {
    return false; /* erased / first boot */
  }
  fs_meta_t tmp;
  memcpy(&tmp, m, sizeof(tmp));
  const uint16_t stored = tmp.crc;
  tmp.crc = 0;
  if (fsCrc16((const uint8_t *)&tmp, sizeof(tmp)) != stored) {
    return false; /* torn write: fall back to cold defaults */
  }
  s_ota = tmp.ota;
  s_ota_flash = tmp.ota;
  s_sched_count = tmp.sched_count < SCHED_MAX_ENTRIES ? tmp.sched_count
                                                      : SCHED_MAX_ENTRIES;
  memcpy(s_sched, tmp.sched, sizeof(s_sched));
  s_sched_persisted = s_sched_count > 0;
  memcpy(s_fdict, tmp.fdict, sizeof(s_fdict));
  s_fdict_count = tmp.fdict_count < FDICT_MAX_ENTRIES ? tmp.fdict_count
                                                      : FDICT_MAX_ENTRIES;
  memcpy(s_fdict_hash, tmp.fdict_hash, 8);
  s_fdict_hash_locked = tmp.fdict_hash_locked != 0;
  s_fdict_initialised = true;
  return true;
#else
  return false; /* host builds: the RAM mirrors already persist */
#endif
}

static void fsMetaSave(void) {
#if defined(ARDUINO_ARCH_RP2040)
  fs_meta_t m = {0};
  m.magic = FS_META_MAGIC;
  m.version = FS_META_VERSION;
  m.ota = s_ota;
  m.sched_count = s_sched_count;
  memcpy(m.sched, s_sched, sizeof(m.sched));
  memcpy(m.fdict, s_fdict, sizeof(m.fdict));
  m.fdict_count = s_fdict_count;
  memcpy(m.fdict_hash, s_fdict_hash, 8);
  m.fdict_hash_locked = s_fdict_hash_locked ? 1 : 0;
  m.crc = 0;
  m.crc = fsCrc16((const uint8_t *)&m, sizeof(m));
  static uint8_t s_write_buf[FS_META_WRITE_SIZE]; /* .bss: RAM, single writer
                                                   * (the worker core). */
  memset(s_write_buf, 0xFF, sizeof(s_write_buf)); /* erased-flash fill for
                                                   * the padded tail */
  memcpy(s_write_buf, &m, sizeof(m));
  /* RP2040 dual-core + IRQ hazard (pico-sdk flash.h, read 2026-10-31):
   * flash_range_erase/program disconnect XIP for the whole operation
   * (the erase/program runs from ROM, but the XIP port is off). During
   * that window (a) ANY other core executing flash-resident code cannot
   * fetch instructions -- flash.h: "unsafe if the other core is
   * executing from flash" -- and (b) any IRQ that fires needs its
   * vector from flash (the vector table is XIP-resident), so a live
   * interrupt also faults the issuing core. A naked call therefore
   * killed the board on its FIRST fsMetaSave after boot (the 0x1E
   * sched wipe in the bench defaults): zombie, power-cycle-only,
   * 2/2 reproducible.
   *
   * Core1 is parked with the ARDUINO-PICO FRAMEWORK's own mechanism
   * (rp2040.idleOtherCore / resumeOtherCore), NOT pico-sdk's
   * multicore_lockout_*: the framework already claims the SIO FIFO
   * IRQ on both cores (_MFIFO::registerCore, installed before setup())
   * and its RAM-resident _irq handler parks the victim exactly for
   * flash writes (RP2040Support.h: "When flash erase/write is
   * completed, resumeOtherCore to return"). Installing pico-sdk's
   * victim_init on top overwrote the framework's vector and bricked
   * boot (EP0 -110, 3/3 after the 2026-10-31 flash) -- so the
   * lockout API is deliberately NOT used here. IRQs on core0 are
   * masked around the operation (the ~50-250 ms of deferred IRQs is
   * harmless: USB OUT is NAKed and the host retransmits, SysTick
   * drifts, radio DIO tolerates it). Timing uses the hardware timer
   * because millis() is SysTick-IRQ-driven and frozen while IRQs are
   * masked. */
  rp2040.idleOtherCore();
  uint32_t irq_mask = save_and_disable_interrupts();
  const uint32_t t0 = time_us_32();
  flash_range_erase(FS_META_SECTOR_OFFS, FS_META_SECTOR_SIZE);
  const uint32_t t1 = time_us_32();
  flash_range_program(FS_META_SECTOR_OFFS, s_write_buf, FS_META_WRITE_SIZE);
  const uint32_t t2 = time_us_32();
  restore_interrupts(irq_mask);
  rp2040.resumeOtherCore();
  if (Serial.availableForWrite() > 96) {
    Serial.printf("[LAB] FSWRITE erase=%luus prog=%luus ms=%lu\r\n",
                  (unsigned long)(t1 - t0), (unsigned long)(t2 - t1),
                  (unsigned long)millis());
  }
#endif
}

void fsLockoutInit(void) {
#if defined(ARDUINO_ARCH_RP2040)
  /* INTENTIONALLY A NO-OP (2026-10-31). pico-sdk's
   * multicore_lockout_victim_init() claims the SIO FIFO IRQ on the
   * calling core with irq_set_exclusive_handler -- but the arduino-pico
   * framework already claimed that exact IRQ on BOTH cores in
   * _MFIFO::registerCore() (main(), before setup()) for its
   * idleOtherCore/resumeOtherCore core-parking mechanism. The overwrite
   * bricked boot: the board attached (D+ pull-up from TinyUSB init)
   * then NAKed every EP0 transfer (kernel: device descriptor read/64,
   * error -110; xhci port power cycle, then total silence), 3/3
   * reproducible after the 2026-10-31 flash. fsMetaSave therefore uses
   * the framework's mechanism instead, which needs no extra init.
   * Kept (and called from both cores) so the call sites document where
   * a future lockout-based fix would initialize. */
  (void)0;
#endif
}

/* ------------------------------------------------------- boot / commit */
void labExecContingency(void) {
  for (uint8_t i = 0; i < FDICT_MAX_ENTRIES; i++) {
    if (s_fdict[i].apid != 0xFFFF && s_fdict[i].apid != 0) {
      labInjectTc(s_fdict[i].apid, s_fdict[i].payload, s_fdict[i].len,
                  LAB_SRC_INTERNAL);
    }
  }
}

void fsBoot(void) {
  /* ==== power-on load of the meta sector ====
   * RP2040 build: the meta sector lives in the tail 4 KB of boot flash
   * (fsMetaLoad) and survives resets + power cycles, exactly like the
   * simulator's flash dict. Host/sim build: the RAM mirrors deliberately
   * survive simulated reboots. */
  if (!s_meta_valid) {
    if (!fsMetaLoad()) {
      memset(&s_ota, 0, sizeof(s_ota));
      s_ota.arwc = 7; /* operator burned 7 updates worth of history */
      s_ota.arwc_enforce = 0; /* V-38 default: rollback allowed */
      s_ota.sig_required = 0; /* V-18 default: unsigned images accepted */
      s_ota.active_slot = 0;
      s_ota.pending_boot = 0;
      s_ota.booted_slot = 0;
    }
    s_meta_valid = true;
  } else {
    s_ota = s_ota_flash;
  }

  /* pending B-slot boot with try limit (watchdog-confirm flow) */
  if (s_ota.pending_boot) {
    s_ota.boot_try_count++;
    if (s_ota.boot_try_count > 3) {
      s_ota.active_slot = 0;
      s_ota.pending_boot = 0;
      s_ota.booted_slot = 0;
    } else {
      s_ota.booted_slot = 1;
    }
  }
  if (!s_fdict_initialised) {
    fdictDefaults();
    s_fdict_initialised = true;
  }
}

void fsCommit(void) {
  s_ota_flash = s_ota; /* host/sim in-process reboot mirror */
#if defined(ARDUINO_ARCH_RP2040)
  fsMetaSave(); /* real meta sector: tail 4 KB of boot flash */
#endif
}
