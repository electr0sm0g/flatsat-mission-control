/*  - labhooks.h
 *
 * flatsat-lab vulnerable firmware v2 -- cross-module hooks.
 *
 * worker.cpp keeps its context static (like upstream); the extension
 * modules reach mission state through these accessors, implemented at the
 * bottom of worker.cpp. Everything a PoC can touch from the wire is here.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_LABHOOKS_H
#define FIRMWARE_LABHOOKS_H
#include "mission.h"
#include "spp.h"
#include <Arduino.h>

/* --- V-24 bench diagnostic counters (defined in firmware.ino) ---------- */
/* Per-pass loop instrumentation: max statement duration (ms) and the
 * statement that produced it, plus the number of >100 ms statements
 * since the previous readout. The 1 Hz FEED line (extcmds.cpp) prints
 * and resets them -- diagnostics that survive console backpressure,
 * unlike the gated LOOP SLOW / RX SLOW printfs. */
extern volatile uint16_t s_loop_max_ms;
extern volatile uint32_t s_loop_slow_cnt;
extern char s_loop_max_tag[8];

/* --- injected TC sources (internal replay paths, V-19/V-20) --- */
#define LAB_SRC_RADIO 0
#define LAB_SRC_USB 1
#define LAB_SRC_INTERNAL 2
#define LAB_SRC_SPACECAN 3
void labInjectTc(uint16_t apid, const uint8_t *payload, uint16_t len,
                 uint8_t source);

/* --- telemetry plumbing ------------------------------------------------ */
/* Build + dispatch one TM (AES-wrapped per secure-link state, padded per
 * covert padding mode). Mirrors the static telemetrySPP* family. */
void labTmSend(uint16_t apid, const uint8_t *data, uint16_t data_len,
               bool force_cleartext);
void labTmError(const char *message);

/* --- mission state accessors ------------------------------------------- */
uint8_t labMissionMode(void);
void labApplyMissionMode(uint8_t mode);          /* missionApplyMode */
uint8_t labStatusFlags(void);                    /* missionStatusFlags */
uint8_t labExtFlags(void);                       /* LAB_FLAG2_* extension byte */
void labPayloadArmedSet(bool armed);
bool labSecureLinkEnabled(void);
void labSecureLinkSetEnabled(bool enabled);
bool labUsbDebugEnabled(void);
void labUsbDebugEnabledSet(bool enabled);
bool labGsModeEnabled(void);
void labGsModeSet(bool enabled);                 /* V-13 overflow / V-21 */
uint32_t labGsChallengeValue(void);
uint32_t labGsExpectedResponseFor(uint32_t challenge);
/* V-28 bench parity: the ground station's last-synced mission clock.
 * hLabStatus (0x26) records millis() when it serves a LAB_STATUS; the GS
 * challenge generator seeds from that value (the mission clock the ground
 * station last SAW, which is the value the simulator's perfectly synced
 * ground station clock holds) instead of the live millis() at generation
 * time. */
void labMarkLabStatusSync(uint32_t ms);
uint32_t labLastLabSyncMs(void);
/* V-24: count one radio-sourced TC for the EWMA TC-rate channel. */
void labCountRadioTc(void);
bool labGsSessionActive(void);
uint16_t labTmCounter(void);                     /* spp TM count (for CTR) */

/* beacon rate control (V0-14 reuse) */
void labSetBeaconIntervalMs(uint32_t interval_ms);

/* --- bench feed window (V-19 parity) ------------------------------------
 * The harness' advance() is a TIME WINDOW: flatsat_sim.py advances its
 * mission model, FDIR, scheduler and radio TM workers ONLY inside
 * advance() (_workers_tick). The board mirrors that with a window-only
 * EPOCH clock: labBenchMs() advances 1:1 with wall time only while a
 * FEED window is open (LAB_CTRL sub 6 FEED_START .. sub 5 SYNC / window
 * deadline), frozen across the inter-window TC phase. The mission model,
 * FDIR, the schedule queue and the periodic radio workers are driven from
 * that clock (extcmds.cpp / mission_model.cpp / fdir.cpp / worker.cpp). */
bool labFeedActive(void);   /* true while a FEED window is open */
uint32_t labBenchMs(void);  /* the window-only epoch clock (ms) */
void labResetRadioWorkerPhase(void); /* re-anchor radio workers (REARM) */

/* --- crash / hang / reboot (V-15, V-21, V-34, V0-15) -------------------- */
void labFatalHang(void);   /* while(1) with no watchdog armed == mission loss */
void labReboot(void);      /* softwareReset() path: preserves watchdog scratch */
void labRebootBrownout(void); /* V-34: same reset surface as a power brownout */
uint32_t labBootCount(void);
uint32_t labWatchdogScratch(uint8_t index);      /* 0..7, survives labReboot */
void labWatchdogScratchSet(uint8_t index, uint32_t value);
bool labPersistentCookiePresent(void);           /* scratch[7] magic (V-21) */
void labBootInit(void);  /* firmware.ino setup(): boot count, cookie effects,
                          * sched replay, OTA slot decision, sdls boot */

/* --- uplink radio stats (V-03 / V-29) ----------------------------------- */
void labRadioLastStats(int *rssi, float *snr, float *freq_error);
/* Harness override (LAB_CTRL inject): when armed, labRadioLastStats returns
 * the given synthetic figures instead of the SX1262 readings, so a bench
 * USB-only setup can still drive the RSSI/freq-error oracles. Sticky. */
void labRadioStatsOverride(int rssi, float snr, float freq_error, bool armed);

/* --- harness radio bridge (LAB_CTRL, bench bring-up over USB only) ------- */
/* Re-enter the full radio command pipeline (SDLS, secure link, GS gate,
 * TC stats) with a raw SPP frame, as if it had been received on air. */
void labInjectFrameAsRadio(uint8_t *frame, uint16_t len);
bool labPayloadArmed(void);

/* --- RCE symbol table (V-14): target values the MEMCPY primitive can
 * retarget SCB->VTOR onto. The ground station's symbol table (what a real
 * attacker recovers from the public firmware binary, and what the PoCs
 * write) is the FIXED synthetic table shared with the Python simulator
 * (flatsat_sim.py SYMBOLS); the `fn` pointer is the real mission function
 * the takeover model fires in software (on silicon the takeover completes
 * when the next IRQ vectors through the rewritten table -- the effect is
 * fired deterministically here so the telemetry reflects it immediately,
 * mirroring the simulator's _rce()). ------------------------------- */
typedef struct {
  const char *name;
  uint32_t addr;   /* the value a VTOR write must equal to be recognised */
  void (*fn)(void); /* the mission function the takeover fires */
} lab_symbol_t;
#define LAB_SYMBOL_COUNT 6
const lab_symbol_t *labSymbolTable(void);
/* Called when a MEMCPY write lands on SCB->VTOR: if the new value matches
 * a known function, the next interrupt executes it (RP2040: automatically;
 * simulator: modelled). Returns the symbol name or NULL. */
const char *labVtorRedirectCheck(uint32_t new_vtor);

/* V-05 bench parity: the GS challenge as served at SYM_GS_CHALLENGE. */
uint32_t labGsChallengeGet(void);

#endif // FIRMWARE_LABHOOKS_H
