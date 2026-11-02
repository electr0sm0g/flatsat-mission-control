/*  - led.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_LED_H
#define FIRMWARE_LED_H
#include <Arduino.h>

#define colorSaturation 60
#define LED_PIXEL_COUNT (1)

typedef enum {
  LED_COLOR_RED,
  LED_COLOR_GREEN,
  LED_COLOR_BLUE,
  LED_COLOR_WHITE,
  LED_COLOR_YELLOW
} led_color_t;

void ledConfigure(void);
void ledTurnRed(void);
void ledTurnGreen(void);
void ledTurnBlue(void);
void ledTurnWhite(void);
void ledTurnOff(void);
void ledBlink(uint8_t count, led_color_t color);
/* Non-blocking twin of ledBlink(): request the effect, service it from
 * ledBlinkTick() on the loop cadence (no delay() on the caller's core).
 * Bench fix (V-24) -- the uplink RX handler used to call the blocking
 * ledBlink() inline and starve core0's loop for 3.2 s per packet. */
void ledBlinkRequest(uint8_t count, led_color_t color);
void ledBlinkTick(void);

#endif // FIRMWARE_LED_H