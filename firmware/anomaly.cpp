/*  - anomaly.cpp
 *
 * EWMA / EWV (exponentially weighted mean + variance), one multiply per
 * sample -- sized for Cortex-M0+ without FPU. Alarm when
 *   |x - mu| > z * sqrt(var)
 * The evasion property mirrors the course's LSTM numbers: a drift of
 * <= 5 % per pass stays inside the smoothed residual (alpha=0.05 keeps
 * mu within ~2 % of the slow trend), so an adversary ramping thruster
 * power a few percent per pass is never signalled.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "anomaly.h"
#include <math.h>
#include <string.h>
#if defined(ARDUINO_ARCH_RP2040)
#include <Arduino.h> /* Serial: latch diagnostic (bench console) */
#endif

#define ANOM_ALPHA 0.05f

typedef struct {
  bool primed;
  float mu;
  float var;
} ewma_t;

static ewma_t s_ch[ANOM_CH_COUNT];
static float s_z = 5.0f;
static bool s_enabled = true;
static bool s_alarm = false;
static anomaly_channel_t s_last_ch = ANOM_CH_TILT;

void anomalySetZ(float z) {
  if (z >= 2.5f && z <= 10.0f) {
    s_z = z;
  }
}
float anomalyGetZ(void) { return s_z; }
void anomalySetEnabled(bool on) { s_enabled = on; }
bool anomalyEnabled(void) { return s_enabled; }
bool anomalyAlarmActive(void) { return s_alarm; }
void anomalyAck(void) { s_alarm = false; }
anomaly_channel_t anomalyLastAlarmChannel(void) { return s_last_ch; }

float anomalyChannelMean(anomaly_channel_t ch) {
  return (ch < ANOM_CH_COUNT && s_ch[ch].primed) ? s_ch[ch].mu : 0.0f;
}

void anomalyFeed(anomaly_channel_t ch, float value) {
  if (ch >= ANOM_CH_COUNT || !s_enabled) {
    return;
  }
  ewma_t *e = &s_ch[ch];
  if (!e->primed) {
    e->primed = true;
    e->mu = value;
    e->var = 0.0f;
    return;
  }
  const float diff = value - e->mu;
  e->mu += ANOM_ALPHA * diff;
  e->var = (1.0f - ANOM_ALPHA) * (e->var + ANOM_ALPHA * diff * diff);

  const float resid = value - e->mu; /* post-update residual, course style */
  const float sigma = sqrtf(e->var);
  if (sigma > 1e-6f && fabsf(resid) > s_z * sigma) {
    if (!s_alarm) {
#if defined(ARDUINO_ARCH_RP2040)
      /* Bench diagnostic (V-24): log the exact latch moment with the
       * channel state so a board trip can be diffed against the
       * reference EWMA (values x100, integer formats only). */
      Serial.printf("[WARN] ANOM LATCH ch=%d x=%ld mu100=%ld var100=%ld "
                    "resid100=%ld sig100=%ld z10=%ld\r\n",
                    (int)ch, (long)(value * 100.0f), (long)(e->mu * 100.0f),
                    (long)(e->var * 100.0f), (long)(resid * 100.0f),
                    (long)(sigma * 100.0f), (long)(s_z * 10.0f));
#endif
    }
    s_alarm = true;
    s_last_ch = ch;
  }
}

void anomalyTick(void) {
  /* 1 Hz bookkeeping: alarm is latched until the operator acknowledges it
   * through FDIR_CONFIG sub 4 (keeps the beacon bit honest). */
}
