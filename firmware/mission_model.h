/*  - mission_model.h
 *
 * flatsat-lab vulnerable firmware v2 -- virtual ADCS + EPS on core 0.
 *
 * FlatSat has NO reaction wheels, magnetorquers or power bus: it is an
 * RP2040, two SX1262, a BME280, an accelerometer and a GPS stick. The course
 * impacts (tumble 5 deg/s from magnetorquer spam, EPS 24 V drain, brownout
 * resets) are therefore modelled as an on-board state machine driven by
 * the SAME telecommands a real operator uses (SET_THRUSTER, HEATER). The
 * LIS2DH12 still measures the real bench shake, so the demo is tangible.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_MISSION_MODEL_H
#define FIRMWARE_MISSION_MODEL_H
#include <Arduino.h>

typedef struct {
  float euler_deg[3];  /* roll, pitch, yaw */
  float rate_dps[3];   /* body rates, deg/s */
  float tilt_dps;      /* magnitude used by FDIR/anomaly */
  bool detumble_on;
  bool sb_override;    /* SB ATT_* frames accepted (V-17) */

  /* EPS virtual bus */
  float bus_voltage;   /* volts, nominal 24.0 */
  /* V-34 bench parity: FLOAT like flatsat_sim.py mm["pct"]. A uint8 with
   * round-to-nearest integration fixed the drain at a fixed point
   * (per-tick delta < 0.5 pct at high time scale -> round(pct-delta) ==
   * pct), so the rail never collapsed on silicon while it did in the
   * simulator. Quantised to a byte only at report time. */
  float battery_pct;   /* 0..100 */
  bool heater_on[4];
  bool eclipse;        /* eclipse cycle state */
  float power_w;       /* instantaneous load */
  bool brownout_armed; /* next tick under threshold -> reset */
} mission_model_t;

void missionModelTick(void);          /* called from labTickWorkers */
void missionModelTickReset(void);     /* V-19: re-anchor after bench-epoch reset */
void missionModelBoot(void);          /* charged battery / sunlight */
void missionModelGet(mission_model_t *out);
void missionModelHeater(uint8_t id, bool on);
void missionModelThrusterEffect(uint8_t thruster, uint8_t power); /* from SET_THRUSTER/SC/SB */
void missionModelDetumble(bool on);
void missionModelAdcsEvent(float rate_x_dps, float rate_y_dps, float rate_z_dps,
                           bool from_sb);
void missionModelTimeScale(float scale); /* bench-accelerated eclipse cycles */
float missionModelTimeScale(void);
void missionModelRearmAttitude(void);   /* V-19: cold-boot attitude reference */
float missionModelOrbitClock(void);      /* 0..95 s orbit clock (eclipse < 35) */
void missionModelBatteryOverride(uint8_t pct); /* V-17 fake BATT_REPORT */

#endif // FIRMWARE_MISSION_MODEL_H
