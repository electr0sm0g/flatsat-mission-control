/*  - sb.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "sb.h"
#include "labhooks.h"
#include "mission_model.h"
#include "thruster.h"
#include <string.h>

/* Reference-model tag (flatsat_sim.py _sb_publish, V-17 writeup): the
 * simulator's constant is 0xC0FEEE11, and the PoC byte stream in the
 * evidence cites it. (0xC0FFEE11 was a silicon typo that made the signed
 * defence reject the reference tag on hardware only.) */
#define SB_TRANSPORT_TAG 0xC0FEEE11UL

static bool s_auth_enabled = false; /* CM0050 bus-auth: OFF by default */
static uint8_t s_sensor_mask = 0x03;
static sb_mid_stat_t s_stats[SB_MAX_MID];

bool sbAuthEnabled(void) { return s_auth_enabled; }
void sbSetAuthEnabled(bool on) { s_auth_enabled = on; }
uint8_t sbSensorMask(void) { return s_sensor_mask; }

const sb_mid_stat_t *sbMidStat(uint16_t mid) {
  return (mid < SB_MAX_MID) ? &s_stats[mid] : NULL;
}
void sbResetStats(void) { memset(s_stats, 0, sizeof(s_stats)); }

bool sbPublish(uint16_t mid, const uint8_t *data, uint16_t len,
               uint8_t source) {
  if (mid >= SB_MAX_MID || data == NULL) {
    return false;
  }

  if (s_auth_enabled) {
    if (len < 4) {
      return false;
    }
    const uint32_t tag = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                         ((uint32_t)data[2] << 8) | data[3];
    if (tag != SB_TRANSPORT_TAG) {
      return false; /* unauthenticated publisher rejected (defence demo) */
    }
    data += 4;
    len = (uint16_t)(len - 4);
  }

  sb_mid_stat_t *st = &s_stats[mid];
  st->delivered = 1;
  st->last_source = source;
  st->count++;
  st->last_len = (len > sizeof(st->last_data)) ? sizeof(st->last_data) : len;
  memcpy(st->last_data, data, st->last_len);

  /* subscribers (mission model + FDIR inputs) act on the latest value --
   * "consumers act on the latest valid-looking message", LM-0002. */
  switch (mid) {
  case SB_MID_ATT_RATE:
    if (len >= 6) {
      const int16_t rx = (int16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
      const int16_t ry = (int16_t)((uint16_t)data[2] | ((uint16_t)data[3] << 8));
      const int16_t rz = (int16_t)((uint16_t)data[4] | ((uint16_t)data[5] << 8));
      missionModelAdcsEvent(((float)rx) / 100.0f, ((float)ry) / 100.0f,
                            ((float)rz) / 100.0f, true);
    }
    break;
  case SB_MID_SENSOR_ENABLE:
    if (len >= 1) {
      s_sensor_mask = data[0];
    }
    break;
  case SB_MID_HEATER_CMD:
    if (len >= 2) {
      missionModelHeater(data[0], data[1] != 0);
    }
    break;
  case SB_MID_BATT_REPORT:
    if (len >= 1) {
      missionModelBatteryOverride(data[0]);
    }
    break;
  case SB_MID_THR_CMD:
    if (len >= 2) {
      thrusterSetT0Power(data[0]);
      thrusterSetT1Power(data[1]);
      missionModelThrusterEffect(0, data[0]);
      missionModelThrusterEffect(1, data[1]);
    }
    break;
  default:
    break; /* no subscriber: delivered-and-ignored, like real SB */
  }
  return true;
}
