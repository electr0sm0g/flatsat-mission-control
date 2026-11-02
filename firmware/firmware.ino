/*  - main.ino
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "led.h"
#include "rdownlink.h"
#include "ruplink.h"
#include "sensors.h"
#include "spacecan.h"
#include "usbCDC.h"
#include "worker.h"
#include "labhooks.h"
#include "flashstore.h"
#if defined(ARDUINO_ARCH_RP2040)
#include "hardware/watchdog.h"
#endif

typedef struct {
  const unsigned long inverval;
  unsigned long previous;
} timeout_worker_t_t;

static timeout_worker_t_t t_tra = {.inverval = 5000, .previous = 0};

void setup() {
#if defined(ARDUINO_ARCH_RP2040)
  /* labRebootBrownout() force-resets through the watchdog, which stays
   * armed (1 ms) across the reboot: disarm before anything can block, or
   * the chip boot-loops forever and the USB device never comes up. */
  if (watchdog_caused_reboot()) {
    watchdog_disable();
  }
  fsLockoutInit(); /* core0 side of the flash multicore lockout (must
                    * precede the first fsMetaSave; the 0x1E wipe in the
                    * bench defaults is the first meta write after boot) */
#endif
  obcSetupUSB();
  ledConfigure();
  obcConfigureCore0();
  sensorsConfigure();
  uplinkRadioConfigure();
  downlinkRadioConfigure();
  uplinkRadioRegisterCb(commandHandlerRadio);
  obcUSBPacketRecivedCallback(commandHandlerUSB);
  ledTurnWhite();
  delay(500);
  ledTurnOff();

  /* flatsat-lab v2: boot-count from watchdog scratch, OTA slot decision,
   * persistence-cookie effects (V-21), scheduled-TC replay (V-19), SDLS
   * and FDIR power-on defaults. */
  labBootInit();
}

void setup1() {
  obcConfigureCore1();
  fsLockoutInit(); /* core1 side: loop1() runs from XIP, so it MUST be
                    * lockout-ready before core0's first flash op */
}

/* Bench diagnostic (V-24): flag any loop statement that takes more than
 * 100 ms (the anomaly feed and the bridge RX ride on this loop). The
 * per-pass counters are ALSO piggybacked on the 1 Hz FEED line
 * (extcmds.cpp): the printf diagnostics are gated on console space and
 * self-suppress exactly when the console is backpressured, while the
 * FEED line is the one console output the lab can always trust. */
volatile uint16_t s_loop_max_ms = 0;
volatile uint32_t s_loop_slow_cnt = 0;
char s_loop_max_tag[8] = {0};

static void loopHbRecord(const char *tag, unsigned long d) {
  if (d > 100UL) {
    s_loop_slow_cnt++;
  }
  if (d > s_loop_max_ms) {
    s_loop_max_ms = (d > 0xFFFFUL) ? 0xFFFF : (uint16_t)d;
    strncpy(s_loop_max_tag, tag, sizeof(s_loop_max_tag) - 1);
    s_loop_max_tag[sizeof(s_loop_max_tag) - 1] = '\0';
  }
}

static unsigned long loopHb(const char *tag, unsigned long t0) {
  const unsigned long d = millis() - t0;
  loopHbRecord(tag, d);
  if (d > 100UL && Serial.availableForWrite() > 96) {
    Serial.printf("[LAB] LOOP SLOW %s took=%lu ms=%lu\r\n",
                  tag, (unsigned long)d, (unsigned long)millis());
  }
  return d;
}

void loop() {
  unsigned long lt;
  lt = millis();
  obcUSBRecv(); /* flatsat-lab v2.1: USB RX parse on core0. Core1 polled the
                 * bridge CDC while core0 wrote TMs on the SAME TinyUSB CDC;
                 * TinyUSB is not multicore-safe and core1 wedged
                 * deterministically after the first MEM_READ (0x19) TC --
                 * the craft kept telemetering (core0) but went deaf to every
                 * TC until a power cycle (observed 2026-10-31). Parse +
                 * drain on one core matches the single-context simulator. */
  loopHb("USB", lt);
  lt = millis();
  commandUsbDrainRing();
  loopHb("DRAIN", lt);
  lt = millis();
  core1StallAlarm();
  loopHb("STALL", lt);
  lt = millis();
  gpsPoll();
  loopHb("GPS", lt);
  lt = millis();
  uplinkRadioCheckPacketReceived();
  loopHb("RADIO-UP", lt);
  lt = millis();
  downlinkRadioCheckTransmition();
  loopHb("RADIO-DN", lt);
  lt = millis();
  telemetryRadioWorker();
  loopHb("TELEM", lt);
  lt = millis();
  if (consoleSensorModeActive()) {
    telemetryDashboardWorker();
  }
  consoleWorker();
  loopHb("CONSOLE", lt);
  ledBlinkTick(); /* V-24: non-blocking LED blink service (no delay) */
}

void loop1() {
  /* USB RX moved to core0 (see loop()); core1 only ticks now. core0's
   * console worker raises a WARN every 10 s if this counter stops. */
  s_core1_tick++;
}
