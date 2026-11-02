/*  - worker.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_WORKER_H
#define FIRMWARE_WORKER_H
#include <Arduino.h>

void telemetrySCWorker(void);
void telemetryRadioWorker(void);
void telemetryDashboardWorker(void);
void commandHandler(uint8_t *buffer, uint16_t buffer_len);
void commandHandlerRadio(uint8_t *buffer, uint16_t buffer_len);
void commandHandlerUSB(uint8_t *buffer, uint16_t buffer_len);
/* Call from core0's loop(): drains USB TC frames (same-core queue since
 * the v2.1 single-core USB RX move). */
void commandUsbDrainRing(void);
/* core1 liveness watchdog (firmware.ino loop1 ticks s_core1_tick). */
extern volatile uint32_t s_core1_tick;
void core1StallAlarm(void);
#endif // FIRMWARE_WORKER_H
