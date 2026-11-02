/*  - led.ino
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "led.h"
#include "pins.h"
#include <NeoPixelBus.h>

NeoPixelBus<NeoGrbFeature, NeoWs2812xMethod> strip(LED_PIXEL_COUNT,
                                                   PIN_RGB_LED);

RgbColor ledColor_red(colorSaturation, 0, 0);
RgbColor ledColor_green(0, colorSaturation, 0);
RgbColor ledColor_blue(0, 0, colorSaturation);
RgbColor ledColor_yellow(colorSaturation, colorSaturation, 0);
RgbColor ledColor_white(colorSaturation);
RgbColor ledColor_black(0);

void ledConfigure(void) { strip.Begin(); }

void ledTurnRed(void) {
  strip.SetPixelColor(0, ledColor_red);
  strip.Show();
}

void ledTurnGreen(void) {
  strip.SetPixelColor(0, ledColor_green);
  strip.Show();
}

void ledTurnBlue(void) {
  strip.SetPixelColor(0, ledColor_blue);
  strip.Show();
}

void ledTurnWhite(void) {
  strip.SetPixelColor(0, ledColor_white);
  strip.Show();
}

void ledTurnOff(void) {
  strip.SetPixelColor(0, ledColor_black);
  strip.Show();
}

RgbColor ledColorSelector(led_color_t color) {
  switch (color) {
  case LED_COLOR_RED:
    return ledColor_red;
    break;
  case LED_COLOR_GREEN:
    return ledColor_green;
    break;
  case LED_COLOR_BLUE:
    return ledColor_blue;
    break;
  case LED_COLOR_WHITE:
    return ledColor_white;
    break;
  case LED_COLOR_YELLOW:
    return ledColor_yellow;
    break;
  default:
    return ledColor_red;
    break;
  }
}

void ledBlink(uint8_t count, led_color_t color) {
  for (int i = 0; i < count; i++) {
    strip.SetPixelColor(0, ledColorSelector(color));
    strip.Show();
    delay(200);
    ledTurnOff();
    delay(200);
  }
}

/* flatsat-lab bench fix (V-24): the blocking ledBlink() ran inline on
 * core0's hot loop whenever the physical uplink radio received a
 * packet (8 x 400 ms = 3.2 s of delay() per RX event -- the loop
 * starved, the bridge CDC RX ring filled, and the host pacer got
 * NAKed for the duration). Same visual effect, driven by the 1 ms
 * loop cadence instead of delay(): request here, service in
 * ledBlinkTick() from loop(). */
static bool s_blink_active = false;
static uint8_t s_blink_left = 0;
static led_color_t s_blink_color = LED_COLOR_BLUE;
static unsigned long s_blink_next_ms = 0;
static bool s_blink_on = false;

void ledBlinkRequest(uint8_t count, led_color_t color) {
  s_blink_left = count;
  s_blink_color = color;
  s_blink_on = true;
  s_blink_active = true;
  s_blink_next_ms = millis();
  strip.SetPixelColor(0, ledColorSelector(color));
  strip.Show();
}

void ledBlinkTick(void) {
  if (!s_blink_active) {
    return;
  }
  const unsigned long now = millis();
  if (now - s_blink_next_ms < 200UL) {
    return;
  }
  s_blink_next_ms = now;
  if (s_blink_on) {
    ledTurnOff();
    s_blink_on = false;
  } else {
    if (s_blink_left == 0) {
      s_blink_active = false;
      return;
    }
    s_blink_left--;
    strip.SetPixelColor(0, ledColorSelector(s_blink_color));
    strip.Show();
    s_blink_on = true;
  }
}