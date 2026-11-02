/*  - flashstore.h
 *
 * flatsat-lab vulnerable firmware v2 -- persistent store in the external
 * 4 MB QSPI NOR (IS25LP032D on /QSPI_SS,/QSPI_SCK,/QSPI_SD0..3, verified on
 * the FlatSat PCB). On the RP2040 build this serialises into the config
 * sectors behind the dual boot slots using the rom_flash_range_* API; in
 * host/simulator builds it is the dict-backed "flash" the Python mirror
 * keeps across virtual reboots. This is the persistence substrate for:
 *
 *   - OTA A/B slots + manifest + anti-rollback counter (V-18 / V-38)
 *   - the scheduled-telecommand queue replayed at boot (V-19)
 *   - the FDIR contingency dictionary (V-20)
 *   - the optional circular telecommand log (V-23)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_FLASHSTORE_H
#define FIRMWARE_FLASHSTORE_H
#include <Arduino.h>

#define FS_FLASH_SIZE 0x400000UL
#define FS_SLOT_B_ADDR 0x200000UL
#define FS_SLOT_B_SIZE 0x180000UL
#define FS_META_ADDR 0x3FC000UL

#define SCHED_MAX_ENTRIES 16
#define SCHED_MAX_PAYLOAD 64
#define FDICT_MAX_ENTRIES 8
#define FDICT_MAX_PAYLOAD 32
#define TCLOG_CAPACITY 128

void fsBoot(void); /* load meta; decide boot slot (V-18 flow) */
void fsCommit(void);
void fsLockoutInit(void); /* multicore-lockout hook: call from BOTH cores
                            * (core0 setup / core1 setup1) before the first
                            * flash write; required by pico-sdk lockout */

/* ---- CRC-16/CCITT-FALSE used by OTA chunks ---------------------------- */
uint16_t fsCrc16(const uint8_t *data, size_t len);

/* ---- OTA --------------------------------------------------------------- */
typedef struct {
  uint8_t active_slot;      /* 0=A 1=B */
  uint8_t pending_boot;     /* 1 = reboot into B */
  uint8_t boot_try_count;   /* >3 => roll back to A */
  uint32_t arwc;            /* anti-rollback counter */
  uint8_t arwc_enforce;     /* 0 (default) = rollback allowed (V-38) */
  uint8_t sig_required;     /* 0 (default) = unsigned images (V-18) */
  uint8_t image_sig[8];     /* expected image tag (soft secure boot) */
  uint8_t image_hash[8];    /* observed digest of slot B */
  uint32_t image_size;
  uint8_t booted_slot;      /* after fsBoot(): slot actually running */
} fs_ota_status_t;

bool otaPushChunk(uint32_t off, const uint8_t *data, uint16_t len,
                  uint16_t crc);
bool otaActivate(void);
bool otaConfirm(void);
void otaGetStatus(fs_ota_status_t *out);
bool otaArwcSet(uint32_t v);            /* no authorisation (V-38) */
bool otaManifest(const uint8_t sig8[8], uint32_t arwc, uint8_t require);
bool otaRollbackToA(void);

/* ---- scheduled telecommand queue (V-19) -------------------------------- */
typedef struct {
  uint32_t every_s;  /* 0 = one-shot at boot */
  uint16_t apid;
  uint8_t len;
  uint8_t payload[SCHED_MAX_PAYLOAD];
  uint32_t next_due_s;
} sched_entry_t;

bool schedAdd(uint32_t every_s, uint16_t apid, const uint8_t *payload,
              uint8_t len);
bool schedClear(void);
uint8_t schedCount(void);
bool schedGet(uint8_t idx, sched_entry_t *out);
void schedRunDue(uint32_t now_s);    /* injects internal TCs (labInjectTc) */
bool schedPersisted(void);           /* true once written to flash */
void schedReplayAtBoot(void);      /* re-arm entries after reset (V-19) */
/* V-19 bench parity: both the cold-boot replay and the harness REARM
 * (LAB_CTRL sub 4) mark the queue PENDING for the next bench epoch
 * instead of stamping it with the wall-clock second (the board's real
 * boot is ~5 s of model time and would leave the queue fired / FDIR
 * tripped before the PoC's first read). The first FEED window (sub 6)
 * consumes the pending epoch: bench clock restarts, entries due at the
 * epoch second -- the simulator's _cold_boot (e["due"] = now_ms//1000)
 * semantics, first fire on the model-second grid. */
void schedRearm(void);
bool schedEpochFeedStart(void); /* consume the pending epoch (sub 6) */

/* ---- FDIR contingency dictionary (V-20) -------------------------------- */
typedef struct {
  uint16_t apid;
  uint8_t len;
  uint8_t payload[FDICT_MAX_PAYLOAD];
} fdict_entry_t;

uint8_t fdictCount(void);
bool fdictGet(uint8_t idx, fdict_entry_t *out);
bool fdictSet(uint8_t idx, uint16_t apid, const uint8_t *payload, uint8_t len);
bool fdictHashSet(void);   /* burn current table hash (CM0044 analogue) */
bool fdictHashLocked(void);
const uint8_t *fdictHash(void); /* 8 bytes */
/* V-20 bench parity (harness prologue): factory reset of the contingency
 * dictionary (default table, hash wiped, lock released) -- the burned
 * lock is flash-persisted and has no wire unlock, so the prologue must
 * restore the cold-boot reference after every PoC. */
void fdictFactoryReset(void);

/* ---- TC log (V-23) ------------------------------------------------------ */
typedef struct {
  uint32_t millis_stamp;
  uint16_t apid;
  uint16_t seq;
  uint8_t len;
  uint8_t payload[32];
} tclog_entry_t;

void tclSetEnabled(bool on);
bool tclEnabled(void);
void tclAppend(uint16_t apid, uint16_t seq, const uint8_t *payload, uint8_t len);
uint16_t tclCount(void);
bool tclRead(uint16_t idx, tclog_entry_t *out);
uint16_t tclEvicted(void); /* entries lost to ring wrap (eviction attack) */

#endif // FIRMWARE_FLASHSTORE_H
