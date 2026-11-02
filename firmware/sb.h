/*  - sb.h
 *
 * flatsat-lab vulnerable firmware v2 -- minimal publish/subscribe software
 * bus, the cFS Software Bus analogue from course ch.8.2 (OPS-SAT /
 * STP-MSP): routing by Message ID only, no publisher identity by default.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_SB_H
#define FIRMWARE_SB_H
#include <Arduino.h>

#define SB_MID_ATT_QUATERNION 0x101 /* 8 B: 4 x int16 LE (w,x,y,z) x10000 */
#define SB_MID_ATT_RATE 0x102       /* 6 B: 3 x int16 LE deg/s x100 */
#define SB_MID_SENSOR_ENABLE 0x103  /* 1 B: sensor mask (bit0 BME, bit1 ACC) */
#define SB_MID_HEATER_CMD 0x104     /* 2 B: id, on */
#define SB_MID_BATT_REPORT 0x105    /* 2 B: charge pct, 0 */
#define SB_MID_THR_CMD 0x106        /* 2 B: t0 power, t1 power */
#define SB_MID_SYS_EVENT 0x1FF      /* free-form event text */

#define SB_MAX_MID 0x200

typedef struct {
  uint8_t delivered;      /* ever delivered */
  uint8_t last_source;    /* 0=radio 1=usb 2=internal 3=spacecan */
  uint32_t count;
  uint8_t last_len;
  uint8_t last_data[32];
} sb_mid_stat_t;

/* Route a frame. When sbAuthEnabled(), frames must carry the 4-byte
 * transport tag (0xC0FFEE11) as data prefix -- the CM0050-style defence,
 * disabled by default to demo the compromise. Returns false on auth fail. */
bool sbPublish(uint16_t mid, const uint8_t *data, uint16_t len,
               uint8_t source);
bool sbAuthEnabled(void);
void sbSetAuthEnabled(bool on);
uint8_t sbSensorMask(void); /* gated by SB_MID_SENSOR_ENABLE (default 0x03) */
const sb_mid_stat_t *sbMidStat(uint16_t mid);
void sbResetStats(void);

#endif // FIRMWARE_SB_H
