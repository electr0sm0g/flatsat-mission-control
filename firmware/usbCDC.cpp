/*  - usbCDC.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

/* flatsat-lab: pull the USB stack headers in with 'private' members visible
 * so we can inspect/fix the CDC instance assignment of USBRadioLink (see
 * obcConfigureCore1). The macro only affects this translation unit. */
#define private public
#include <Arduino.h>
#include <Adafruit_TinyUSB.h>
#undef private

#include "usbCDC.h"

#define FRAME_HEADER_1 0xAA
#define FRAME_HEADER_2 0x55
#define HEADER_SIZE 4
#define MAX_FRAME_SIZE 1024

static uint8_t rx_buffer[MAX_FRAME_SIZE];
static size_t rx_len = 0;

#define BOARD_VERSION 0x0020 // Current version board 03/2026

Adafruit_USBD_CDC USBRadioLink;

static radioPacketReceivedCb usb_radio_cb = NULL;

void obcSetupUSB(void) {
  TinyUSBDevice.setID(0x239a, 0xcafe);
  TinyUSBDevice.setManufacturerDescriptor("Pwnsat");
  TinyUSBDevice.setProductDescriptor("Pwnsat - Flatsat");
  TinyUSBDevice.setSerialDescriptor("fsat");
  TinyUSBDevice.setDeviceVersion(BOARD_VERSION);
}

static void obcResetUSBStack(void) {
  if (TinyUSBDevice.mounted()) {
    TinyUSBDevice.detach();
    delay(10);
    TinyUSBDevice.attach();
  }
}

static void obcWaitConnectionCore0(void) {
  while (!Serial) {
    delay(1000);
  }
}

static void obcWaitConnectionCore1(void) {
  while (!USBRadioLink) {
    delay(1000);
  }
}

void obcConfigureCore0(void) {
  obcSetupUSB();

  Serial.begin(921600);
  obcWaitConnectionCore0();

  if (CFG_TUD_CDC < 2) {
    Serial.printf(
        "[WARNING] CFG_TUD_CDC must be at least 2, current value is %u\r\n",
        CFG_TUD_CDC);
    return;
  }
  Serial.printf("[INFO] USB Device configured successfully\r\n");
}

/* flatsat-lab: the core's USB Serial registers a CDC WITHOUT going through
 * Adafruit_USBD_CDC::begin(), so our bridge can be handed driver instance 0
 * although the descriptor places if02 SECOND (where TinyUSB's driver maps
 * it to instance 1). Force the correct instance if the counter lied. */
void obcConfigureCore1(void) {
  obcSetupUSB();
  USBRadioLink.begin(921600);
  /* obcUSBRecv() now runs on core0 (single-core TinyUSB access): without a
   * short timeout, Stream::readBytes would block core0's whole mission loop
   * for up to 1 s per frame burst waiting for a full buffer. The bench
   * writes whole frames at once, so 50 ms of idle == end of burst. */
  USBRadioLink.setTimeout(50);

  /* NB: silent here -- core1 must not print on the CDC logged by core0. */
  if (USBRadioLink._instance == 0 && CFG_TUD_CDC > 1) {
    USBRadioLink._instance = 1;
  }

  obcResetUSBStack();
  obcWaitConnectionCore1();
}

void obcUSBPacketRecivedCallback(radioPacketReceivedCb recv_cb) {
  usb_radio_cb = recv_cb;
}

void obcUSBTransmitFrame(uint8_t *buffer, ssize_t buffer_len) {
  USBRadioLink.write(USB_LINK_SYNC_WORD);
  USBRadioLink.write(buffer, buffer_len);
}

static void printHexDump(const uint8_t *data, size_t len) {
  const size_t bytesPerLine = 32;
  char ascii[bytesPerLine + 1];
  ascii[bytesPerLine] = '\0';

  for (size_t i = 0; i < len; i++) {
    if (i % bytesPerLine == 0) {
      if (i != 0) {
        Serial.print("  |");
        Serial.println(ascii);
      }
      Serial.printf("%08X  ", (unsigned int)i);
    }

    Serial.printf("%02X ", data[i]);
    ascii[i % bytesPerLine] = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
  }

  size_t remaining = len % bytesPerLine;
  if (remaining > 0) {
    for (size_t i = remaining; i < bytesPerLine; i++) {
      Serial.print("   ");
    }
  }

  Serial.print("  |");
  ascii[remaining == 0 ? bytesPerLine : remaining] = '\0';
  Serial.println(ascii);
}

void obcUSBRecv(void) {
  /* Bench diagnostic (V-24): catch long inline stalls on the RX path
   * (the TC pipeline runs synchronously here -- a blocking console
   * write or any long handler would show up as a big `took`). */
  const unsigned long rx_t0 = millis();
  size_t rx_drained = 0;
  if (rx_len >= sizeof(rx_buffer)) {
    rx_len = 0;
  }

  while (USBRadioLink.available() > 0 && rx_len < sizeof(rx_buffer)) {
    /* V-24 bench fix: drain ONLY what has actually arrived. The old
     * readBytes(buf, 1024 - rx_len) blocks the full 50 ms stream
     * timeout (Stream::read on an empty ring) whenever a burst
     * arrives mid-frame -- at pacer rates > 20 TC/s that ate the
     * whole frame interval: the loop fell behind, rx_buffer
     * overflowed (dropping complete frames) and the host pacer got
     * NAKed while the EP RX ring stayed full. Guarding every read()
     * on available() makes the drain strictly non-blocking; the
     * loop's natural cadence re-enters here a few times per burst.
     * Single-consumer invariant: core1 never touches USBRadioLink
     * (it only ticks s_core1_tick), the DCD ISR only appends. */
    rx_buffer[rx_len++] = (uint8_t)USBRadioLink.read();
    rx_drained++;
  }
  {
    /* Frame walk over whatever the drain just collected (runs once per
     * obcUSBRecv pass; frames that arrive while the inline pipeline is
     * busy ride to the next loop turn -- a few ms, not 50). */
    size_t offset = 0;
    while (rx_len - offset >= HEADER_SIZE) {
      uint8_t *p = &rx_buffer[offset];

      if (p[0] != FRAME_HEADER_1 || p[1] != FRAME_HEADER_2) {
        offset++;
        continue;
      }

      uint16_t len = (p[2] << 8) | p[3];
      size_t total = HEADER_SIZE + len;

      if (len > MAX_FRAME_SIZE || len == 0) {
        offset += 2;
        continue;
      }

      if (rx_len - offset < total) {
        break;
      }

      if (usb_radio_cb) {
        usb_radio_cb(&p[HEADER_SIZE], len);
        /* NB: no printHexDump here -- core1 must not write the CDC that
         * core0 logs to (TinyUSB is not multicore-safe; it reset the
         * board). The command log lives in core0's pipeline instead. */
      }
      offset += total;
    }

    if (offset > 0) {
      memmove(rx_buffer, rx_buffer + offset, rx_len - offset);
      rx_len -= offset;
    }
  }
  if (millis() - rx_t0 > 500UL) {
    /* One RX pass took more than half a second: the inline TC pipeline
     * blocked somewhere (console backpressure, a long handler, ...).
     * Gated on console space: the diagnostic must not backpressure. */
    if (Serial.availableForWrite() > 96) {
      Serial.printf("[WARN] RX SLOW took=%lu drained=%lu ms=%lu\r\n",
                    (unsigned long)(millis() - rx_t0),
                    (unsigned long)rx_drained, (unsigned long)millis());
    }
  }
}