/*  - mission_model.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Python mirror: flatsat_sim.py :: class MissionModel.
 *
 * Numbers calibrated to the course:
 *   - SET_THRUSTER spam saturates B-dot detumble: torque per tick
 *     +0.3 deg/s^2 * P/255 vs detumble authority 0.25 deg/s^2 max
 *     (P>=213 permanently out-spins detumble -> tumble runs away);
 *   - tumble alarm threshold 5 deg/s (SV-MA-2, OPS-SAT demo);
 *   - eclipse 35 min / orbit 95 min; load: OBC 0.8 W + heater 2.4 W each
 *     + thruster 1.2 W when powered; solar 3.0 W sun / 0 eclipse;
 *   - battery 40 Wh, voltage 21.0 + 3.0*pct/100 (24 V nominal bus);
 *   - brownout under 21.0 V == reset with volatile SRAM state loss (V-34).
 */
#include "mission_model.h"
#include "labhooks.h"
#include "thruster.h"
#include <math.h>
#include <string.h>

#define MM_TICK_MS 100
#define MM_DETUMBLE_MAX_DPS2 0.25f
#define MM_TORQUE_MAX_DPS2 0.3f
#define MM_DAMP_DPS2 0.01f
#define MM_BUS_NOMINAL_V 24.0f
#define MM_BROWNOUT_V 21.0f
#define MM_BATTERY_WH 40.0f
#define MM_ORBIT_S 95.0f
#define MM_ECLIPSE_S 35.0f

static mission_model_t s_mm;
static float s_time_scale = 60.0f; /* bench demo: 1 s real == 60 s orbit */
static unsigned long s_last_tick = 0;
static float s_orbit_clock_s = 0;

void missionModelTimeScale(float scale) {
  if (scale >= 0.1f && scale <= 3600.0f) {
    s_time_scale = scale;
  }
}
float missionModelTimeScale(void) { return s_time_scale; }
float missionModelOrbitClock(void) { return s_orbit_clock_s; }

void missionModelGet(mission_model_t *out) {
  if (out != NULL) {
    *out = s_mm;
  }
}

void missionModelHeater(uint8_t id, bool on) {
  if (id < 4) {
    s_mm.heater_on[id] = on;
  }
}

void missionModelDetumble(bool on) { s_mm.detumble_on = on; }

void missionModelBatteryOverride(uint8_t pct) {
  /* V-17: a forged BATT_REPORT Message ID is trusted verbatim. */
  s_mm.sb_override = true;
  s_mm.battery_pct = pct;
  /* V-19 bench parity: like the simulator's _sb_publish (MID 0x105 sets
   * mm["bus_v"] = 21.0 + 3.0*pct/100 in the same statement), the derived
   * bus voltage is updated HERE at publish time, not only on the next
   * model tick -- the tick is gated to the FEED windows (image G), so a
   * status read without an advance() (v117's post-injection 0x1D check)
   * would otherwise report the stale rail where the sim reports the
   * forged 22.2 V immediately. */
  s_mm.bus_voltage = 21.0f + 3.0f * ((float)pct / 100.0f);
}

void missionModelAdcsEvent(float rx, float ry, float rz, bool from_sb) {
  if (from_sb) {
    /* forged SB ATT_RATE: body rates replaced wholesale */
    s_mm.sb_override = true;
    s_mm.rate_dps[0] = rx;
    s_mm.rate_dps[1] = ry;
    s_mm.rate_dps[2] = rz;
  }
}

void missionModelThrusterEffect(uint8_t thruster, uint8_t power) {
  const float t = MM_TORQUE_MAX_DPS2 * ((float)power / 255.0f);
  if (thruster == 0) {
    s_mm.rate_dps[0] += t; /* roll axis */
  } else {
    s_mm.rate_dps[1] += t; /* pitch axis */
  }
}

/* Power-on electrical state: a freshly booted FlatSat rides a charged
 * battery in sunlight (mirrors flatsat_sim.py MissionModel boot: pct 100,
 * eclipse off). Without this the zero-initialized .bss model boots at
 * battery 0 % / 21.0 V in eclipse, arms the brownout flag, and the FDIR
 * (armed by default) brownout-resets the board every couple of seconds. */
void missionModelBoot(void) {
  s_mm.battery_pct = 100;
  s_mm.bus_voltage = MM_BUS_NOMINAL_V;
  s_mm.eclipse = false;
  s_mm.power_w = 0.8f;
}

void missionModelRearmAttitude(void) {
  /* V-19 bench parity: the simulator's _cold_boot restarts the model at
   * the reset instant (rate/euler zero, tilt 0, detumble off). On
   * silicon the model keeps integrating through the ~5 s real boot, so
   * the harness's REARM (LAB_CTRL sub 4) restores this same cold-boot
   * attitude reference. EPS state is left alone: a soft reset keeps the
   * battery, and the power-event path re-runs missionModelBoot(). */
  s_mm.rate_dps[0] = 0.0f;
  s_mm.rate_dps[1] = 0.0f;
  s_mm.rate_dps[2] = 0.0f;
  s_mm.euler_deg[0] = 0.0f;
  s_mm.euler_deg[1] = 0.0f;
  s_mm.euler_deg[2] = 0.0f;
  s_mm.tilt_dps = 0.0f;
  s_mm.detumble_on = false;
  s_mm.brownout_armed = false;
  s_mm.sb_override = false;
}

void missionModelTick(void) {
  /* V-19 bench parity: the model advances ONLY inside the harness'
   * advance() window (the labBenchMs epoch clock, which runs 1:1 with
   * wall time only while a FEED window is open) -- exactly like
   * flatsat_sim.py _workers_tick, which runs only from advance().
   * s_last_tick is a BENCH-ms stamp: frozen across the inter-window TC
   * phase, so dt never counts wall time the simulator never sees. */
  if (!labFeedActive()) {
    return;
  }
  const uint32_t now = labBenchMs();
  if (s_last_tick == 0) {
    s_last_tick = now;
  }
  if ((uint32_t)(now - s_last_tick) < MM_TICK_MS) {
    return;
  }
  const float dt_real = (float)(now - s_last_tick) / 1000.0f;
  s_last_tick = now;
  const float dt_orbit = dt_real * s_time_scale;

  /* ---- attitude ---- */
  float torque[3] = {0, 0, 0};
  torque[0] += MM_TORQUE_MAX_DPS2 * ((float)thrusterGetT0Power() / 255.0f);
  torque[1] += MM_TORQUE_MAX_DPS2 * ((float)thrusterGetT1Power() / 255.0f);

  for (int axis = 0; axis < 3; axis++) {
    float damp = 0.0f;
    if (s_mm.detumble_on) {
      /* B-dot: commanded torque saturated at MM_DETUMBLE_MAX_DPS2.
       * Like the passive branch, the x10 the reference model applies to
       * the damp term (flatsat_sim.py: - damp * dt_o * 10) is baked in
       * here: without it the saturated authority (0.25) sits BELOW the
       * latched thruster torque (0.3) and detumble can never beat the
       * spam (V-33: the board's tilt crept UP through the recovery
       * window instead of the sim's 0.22 deg/s^2 net decay). */
      float want = MM_TORQUE_MAX_DPS2 * 2.0f * s_mm.rate_dps[axis];
      if (want > MM_DETUMBLE_MAX_DPS2) {
        want = MM_DETUMBLE_MAX_DPS2; /* saturation (course ch.11.1) */
      }
      damp = want * 10.0f;
    } else {
      /* Passive damping: the simulator applies MM_DAMP_DPS2 at 10x this
       * term -- keep silicon at parity, otherwise the default thruster
       * idle power integrates the tilt rate up until FDIR falsely trips. */
      damp = MM_DAMP_DPS2 * 10.0f;
    }
    s_mm.rate_dps[axis] += torque[axis] * dt_orbit;
    s_mm.rate_dps[axis] -= damp * dt_orbit;
    if (s_mm.rate_dps[axis] < 0.0f) {
      s_mm.rate_dps[axis] = 0.0f;
    }
    s_mm.euler_deg[axis] += s_mm.rate_dps[axis] * dt_orbit;
  }
  s_mm.tilt_dps = sqrtf(s_mm.rate_dps[0] * s_mm.rate_dps[0] +
                        s_mm.rate_dps[1] * s_mm.rate_dps[1] +
                        s_mm.rate_dps[2] * s_mm.rate_dps[2]);

  /* ---- EPS ---- */
  s_orbit_clock_s += dt_orbit;
  if (s_orbit_clock_s >= MM_ORBIT_S) {
    s_orbit_clock_s -= MM_ORBIT_S;
  }
  s_mm.eclipse = (s_orbit_clock_s < MM_ECLIPSE_S);

  float load_w = 0.8f; /* OBC always on */
  for (int h = 0; h < 4; h++) {
    if (s_mm.heater_on[h]) {
      load_w += 2.4f;
    }
  }
  if (thrusterGetT0Power() > 0) {
    load_w += 1.2f;
  }
  if (thrusterGetT1Power() > 0) {
    load_w += 1.2f;
  }
  s_mm.power_w = load_w;
  const float solar_w = s_mm.eclipse ? 0.0f : 3.0f;
  const float net_wh = ((solar_w - load_w) * dt_orbit) / 3600.0f;
  /* V-34 bench parity: integrate in FLOAT exactly like flatsat_sim.py
   * (mm["pct"] += ((solar-load)*dt_o/3600)/40*100, clamped). The old
   * uint8 round-to-nearest quantisation created a fixed point whenever
   * the per-tick delta stayed below 0.5 pct (the 655x bench time scale
   * of V-34), so the rail plateaued at ~21.9 V and never collapsed. */
  float pct = s_mm.battery_pct + (net_wh / MM_BATTERY_WH) * 100.0f;
  if (pct > 100.0f) {
    pct = 100.0f;
  }
  if (pct < 0.0f) {
    pct = 0.0f;
  }
  s_mm.battery_pct = pct;
  s_mm.bus_voltage = 21.0f + 3.0f * (s_mm.battery_pct / 100.0f);

  /* Bus regulation cannot hold the rail once the battery is empty and the
   * load still exceeds what the panels deliver: the rail collapses. */
  if (s_mm.bus_voltage < MM_BROWNOUT_V ||
      (s_mm.battery_pct <= 0.0f && solar_w < load_w)) {
    s_mm.brownout_armed = true; /* FDIR/brownout handlers act next tick */
  }
  s_mm.sb_override = false; /* SB values are one-shot truth until re-published */
}

void missionModelTickReset(void) {
  /* V-19 bench parity: re-anchor the model tick after a bench-epoch reset
   * (the first FEED_START after a cold-boot sched replay / harness REARM
   * restarts the bench clock at zero): the next labFeedActive tick
   * re-bases s_last_tick with dt=0, like the simulator's clock restart
   * at the reset instant. */
  s_last_tick = 0;
}
