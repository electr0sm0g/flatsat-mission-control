/*  - anomaly.h
 *
 * flatsat-lab vulnerable firmware v2 -- EWMA anomaly detector (V-24).
 * A 200-line stand-in for the LSTM detectors of course ch.12.2 (SMAP/MSL
 * style): same input idea, same weakness -- slow drift under the smoothing
 * constant never raises the alarm.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_ANOMALY_H
#define FIRMWARE_ANOMALY_H
#include <Arduino.h>

typedef enum {
  ANOM_CH_TILT = 0,   /* deg/s */
  ANOM_CH_TC_RATE = 1,  /* telecommands per second */
  ANOM_CH_POWER = 2,    /* W */
  ANOM_CH_BUS_V = 3,    /* 0.01 V */
  ANOM_CH_COUNT = 4,
} anomaly_channel_t;

void anomalyFeed(anomaly_channel_t ch, float value);
void anomalySetZ(float z);           /* 2.5..10, default 5.0 */
float anomalyGetZ(void);
void anomalySetEnabled(bool on);     /* DEFENSES bit7 */
bool anomalyEnabled(void);
bool anomalyAlarmActive(void);
void anomalyAck(void); /* clears the latched alarm (FDIR ack) */
anomaly_channel_t anomalyLastAlarmChannel(void);
float anomalyChannelMean(anomaly_channel_t ch);
void anomalyTick(void);              /* window bookkeeping, 1 Hz */

#endif // FIRMWARE_ANOMALY_H
