/*  - fdir.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "fdir.h"
#include "anomaly.h"
#include "labhooks.h"
#include "mission_model.h"
#include "sdls_sim.h"
#include <string.h>
#include <Arduino.h>

static bool s_armed = true;
static bool s_safe = false;
/* V-19 bench parity: BENCH-ms stamps (the window-only epoch clock), so the
 * TUMBLE sustain window and the release window are measured in the same
 * time the simulator's _workers_tick measures them in (model-ms inside
 * advance()). The epoch resets that wrap the bench clock (cold boot,
 * harness REARM) zero these stamps via fdirBootDefaults/fdirRearmColdBoot. */
static uint32_t s_safe_entry_ms = 0;
static uint32_t s_triggers = 0;
static char s_last_trigger[24] = "";
static uint32_t s_tilt_over_ms = 0;

void fdirBootDefaults(void) {
  s_armed = true;
  s_safe = false;
  s_safe_entry_ms = 0;
  s_triggers = 0;
  s_last_trigger[0] = '\0';
  s_tilt_over_ms = 0;
}

bool fdirArmed(void) { return s_armed; }
void fdirSetArmed(bool on) { s_armed = on; }
bool fdirSafeActive(void) { return s_safe; }
unsigned long fdirSafeEntryMs(void) { return s_safe_entry_ms; }
uint32_t fdirTriggerCount(void) { return s_triggers; }
const char *fdirLastTrigger(void) { return s_last_trigger; }
bool fdirTestmode(void) { return s_safe; }
bool fdirSafeForceEcb(void) { return s_safe; }
void fdirAckAnomaly(void) { anomalyAck(); }

static void safeEnter(const char *cause) {
  extern void labExecContingency(void); /* flashstore.cpp: V-20 dictionary */
  s_safe = true;
  s_safe_entry_ms = labBenchMs();
  s_triggers++;
  strncpy(s_last_trigger, cause, sizeof(s_last_trigger) - 1);
  s_last_trigger[sizeof(s_last_trigger) - 1] = '\0';
  labApplyMissionMode(MISSION_MODE_SAFE);
  sdlsSetArcRelaxed(true); /* EX-0006.04: ARC window widened in contingency */
  labSecureLinkSetEnabled(false); /* EX-0006.02: null-cipher fallback */
  labExecContingency();           /* EX-0006.05: run the (tamperable) dict */
}

void fdirForceSafe(const char *cause) {
  if (!s_safe && s_armed) {
    safeEnter(cause);
  }
}

void fdirTick(void) {
  /* V-19 bench parity: FDIR advances only inside the harness' advance()
   * window, with the model (the simulator's FDIR block sits inside
   * _workers_tick, which runs only from advance()). The TUMBLE sustain
   * window is measured in bench-ms (model-ms on both benches). */
  if (!labFeedActive()) {
    return;
  }
  if (!s_armed) {
    return;
  }
  mission_model_t mm;
  missionModelGet(&mm);

  const uint32_t now = labBenchMs();
  bool trigger = false;
  const char *cause = "";

  if (mm.tilt_dps > FDIR_TILT_ALARM_DPS) {
    if (s_tilt_over_ms == 0) {
      s_tilt_over_ms = now;
    } else if (now - s_tilt_over_ms > 2000UL) {
      trigger = true;
      cause = "TUMBLE";
    }
  } else {
    s_tilt_over_ms = 0;
  }

  if (!trigger && mm.bus_voltage < FDIR_BUS_SAFE_V) {
    trigger = true;
    cause = "BUS_UNDERV";
  }

  if (trigger && !s_safe) {
    safeEnter(cause);
  }

  /* brownout (V-34): below MM threshold == mission-ending reset, with the
   * volatile SRAM security state lost exactly like the course's EPS case. */
  if (mm.brownout_armed) {
    labRebootBrownout();
  }
}

bool fdirRequestExit(const char **reason) {
  if (!s_safe) {
    if (reason) {
      *reason = "NOT SAFE";
    }
    return false;
  }
  /* Release window in bench-ms: the simulator's FDIR_RELEASE_MS gate runs
   * on the model clock (now_ms - fdir_entry), which the bench clock
   * mirrors 1:1 inside the windows. */
  const uint32_t now = labBenchMs();
  if (now - s_safe_entry_ms < FDIR_RELEASE_WINDOW_MS) {
    if (reason) {
      *reason = "RELEASE WINDOW";
    }
    return false;
  }
  mission_model_t mm;
  missionModelGet(&mm);
  if (mm.tilt_dps > FDIR_TILT_ALARM_DPS || mm.bus_voltage < FDIR_BUS_SAFE_V) {
    if (reason) {
      *reason = "TRIGGER ACTIVE";
    }
    return false;
  }
  s_safe = false;
  sdlsSetArcRelaxed(false);
  labApplyMissionMode(MISSION_MODE_NOMINAL);
  return true;
}

void fdirRearmColdBoot(void) {
  /* V-19 bench parity: see fdir.h. After a mid-PoC reset the real boot
   * has already re-armed the module (s_safe/s_tilt_over_ms are statics),
   * so this only matters if safe mode latched DURING the boot window
   * (sustained idle-thruster torque at the 60x bench scale) -- in which
   * case it clears it WITHOUT the fdirRequestExit() gates, exactly like
   * the simulator's _cold_boot does. */
  s_tilt_over_ms = 0;
  if (s_safe) {
    s_safe = false;
    sdlsSetArcRelaxed(false);
    labApplyMissionMode(MISSION_MODE_NOMINAL);
  }
}
