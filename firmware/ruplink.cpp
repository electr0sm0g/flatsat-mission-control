/*  - ruplink.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "ruplink.h"
#include "led.h"
#include "pins.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>

static SPIClassRP2040 spiRadio0(spi0, PIN_SPI_RADIO0_CIPO, PIN_RADIO0_NSS,
                                PIN_SPI_RADIO0_SCK, PIN_SPI_RADIO0_COPI);
SX1262 radio0 = new Module(PIN_RADIO0_NSS, PIN_RADIO0_DIO1, PIN_RADIO0_RST,
                           PIN_RADIO0_BSY, spiRadio0);

static radioPacketReceivedCb radi_recv_cb = NULL;
static uint32_t s_crc_errors = 0; /* V-12: frames accepted despite CRC mismatch */

volatile bool receivedFlag = false;
volatile bool enableInterruptRadio = true;

static void log_line(const char *type, const char *msg) {
  Serial.printf("[%s] %s\r\n", type, msg);
}

static int hexCharToNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static size_t hexStringToBytes(const uint8_t *input, size_t len,
                               uint8_t *output) {
  size_t outIndex = 0;

  for (size_t i = 0; i < len;) {
    if (input[i] == ' ') {
      i++;
      continue;
    }

    if (i + 1 >= len)
      break;

    int high = hexCharToNibble(input[i]);
    int low = hexCharToNibble(input[i + 1]);

    if (high < 0 || low < 0)
      break;

    output[outIndex++] = (high << 4) | low;
    i += 2;
  }

  return outIndex;
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

static void radio_received_flag(void) {
  if (!enableInterruptRadio) {
    return;
  }
  receivedFlag = true;
}

void uplinkRadioRegisterCb(radioPacketReceivedCb recv_cb) {
  radi_recv_cb = recv_cb;
}

void uplinkRadioConfigure(void) {
  spiRadio0.begin();

  // Explicit tcxoVoltage=0.0 -- RadioLib's
  // default is 1.6V, which tells the chip to wait for a TCXO to
  // stabilize. If this module uses a plain XTAL (no TCXO), that wait
  // never completes and calibration inside config() fails with -707
  // (RADIOLIB_ERR_SPI_CMD_FAILED). freq/bw/sf/cr/syncWord/power/
  // preambleLength are left at RadioLib's defaults since they get
  // explicitly reconfigured below anyway.
  int state = radio0.begin(434.0, 125.0, 9, 7, RADIOLIB_SX126X_SYNC_WORD_PRIVATE,
                           10, 8, 0.0, false);
  if (state != RADIOLIB_ERR_NONE) {
    log_line("ERROR", "Radio 0 Init Failed");
    Serial.printf("Error: %d\r\n", state);
    return;
  }
  radio0.setFrequency(UPLINK_FREQ);
  radio0.setBandwidth(UPLINK_BW);
  radio0.setSpreadingFactor(UPLINK_SF);
  radio0.setCodingRate(UPLINK_CR);
  radio0.setOutputPower(22);
  radio0.setRfSwitchPins(RADIOLIB_NC, PIN_RADIO0_ANT_SW);
  radio0.setPacketReceivedAction(radio_received_flag);
  radio0.explicitHeader();
  radio0.setCRC(0);
  radio0.startReceive();
  log_line("INFO", "Radio 0 Configured Successfully!");
}

void uplinkRadioCheckPacketReceived(void) {
  if (receivedFlag) {
    /* Bench diagnostic (V-24): timestamp the RX pipeline steps -- a
     * spurious physical packet used to cost 6+ s of core0 time here
     * (blocking ledBlink + SPI/BSY waits) and the 6401 ms stalls had
     * to be attributed to a specific step. Gated on console space. */
    const unsigned long t_rx0 = millis();
    unsigned long t_len, t_read, t_cb;
    receivedFlag = false;
    enableInterruptRadio = false;

    int recvLen = radio0.getPacketLength();
    /* Bench hardening (V-24): a spurious/floating DIO1 interrupt used
     * to hand the stack a VLA sized by an unvalidated radio length.
     * The SX1262 explicit-header payload is <= 255 bytes; clamp so a
     * garbage length can never blow core0's stack. */
    if (recvLen <= 0 || recvLen > 255) {
      enableInterruptRadio = true;
      radio0.startReceive();
      return;
    }
    t_len = millis();

    byte byteArr[256];
    int state = radio0.readData(byteArr, recvLen);
    t_read = millis();
    if (state == RADIOLIB_ERR_NONE || state == RADIOLIB_ERR_CRC_MISMATCH) {
      if (state == RADIOLIB_ERR_CRC_MISMATCH) {
        s_crc_errors++;
      }
      if (radi_recv_cb != NULL) {
        printHexDump(byteArr, recvLen);
        uint8_t parsed[256];
        size_t parsedLen = hexStringToBytes(byteArr, recvLen, parsed);
        radi_recv_cb(byteArr, recvLen);
      } else {
        Serial.print("[INFO] Radio 0 Recv: ");
        Serial.write(byteArr, recvLen);
        Serial.println();
        uint8_t parsed[256];
        size_t parsedLen = hexStringToBytes(byteArr, recvLen, parsed);

        Serial.println("[INFO] Parsed HEX -> RAW:");
        printHexDump(parsed, parsedLen);
        printHexDump(byteArr, recvLen);
        Serial.print("[INFO] Radio 0 RSSI: ");
        Serial.println(radio0.getRSSI());
        Serial.print("[INFO] Radio 0 SNR: ");
        Serial.println(radio0.getSNR());
      }
      /* V-24 bench fix: the blocking ledBlink(8) = 3.2 s of delay() on
       * core0's hot loop (it ran inline here once per physical RX
       * event and starved the bridge-CDC drain for the duration).
       * Same visual effect, serviced from ledBlinkTick() in loop(). */
      ledBlinkRequest(8, LED_COLOR_BLUE);
    } else {
      Serial.print("[SYS - Radio] Recv Error: ");
      Serial.println(state);
    }
    t_cb = millis();

    radio0.startReceive();
    enableInterruptRadio = true;
    if (Serial.availableForWrite() > 96) {
      Serial.printf("[LAB] RADIO RX len=%d len=%lu rd=%lu cb=%lu rx=%lu "
                    "total=%lu\r\n",
                    (int)recvLen, (unsigned long)(t_len - t_rx0),
                    (unsigned long)(t_read - t_len),
                    (unsigned long)(t_cb - t_read),
                    (unsigned long)(millis() - t_cb),
                    (unsigned long)(millis() - t_rx0));
    }
  }
}
/* ---- flatsat-lab v2 hooks (V-03 RSSI oracle, V-12 CRC posture) ---- */
void radioLastStats(int *rssi, float *snr, float *freq_error) {
  if (rssi != NULL) {
    *rssi = radio0.getRSSI();
  }
  if (snr != NULL) {
    *snr = radio0.getSNR();
  }
  if (freq_error != NULL) {
    *freq_error = radio0.getFrequencyError();
  }
}

void uplinkRadioSetCrc(bool on) {
  radio0.setCRC(on ? 1 : 0); /* DEF_RADIO_CRC countermeasure (off by
                              * default -- bit flips then stay invisible) */
}

uint32_t uplinkRadioCrcErrors(void) {
  return s_crc_errors;
}
