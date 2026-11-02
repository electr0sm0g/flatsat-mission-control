/*  - spacecan.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Software-simulated SpaceCAN bus console, ported from spacecan_lib's frame
 * format and reassembly logic. Reachable only through the existing debug
 * Serial console via a text command toggle (no new USB endpoint, no changes
 * to the SPP/radio command path).
 */
#ifndef FIRMWARE_SPACECAN_H
#define FIRMWARE_SPACECAN_H
#include <Arduino.h>

#define SC_MAX_FRAGMENTS 43
#define SC_MAX_PACKET_SIZE 256
#define SC_MAX_DATA_LEN 8
#define SC_PAYLOAD_HEADER_LEN 2
#define SC_MAX_CHUNK_LEN (SC_MAX_DATA_LEN - SC_PAYLOAD_HEADER_LEN)
#define SC_REASSEMBLY_TIMEOUT_MS 500

#define SC_CAN_FUNCTION_MASK 0x780
#define SC_CAN_NODE_MASK 0x07F
#define SC_CANID_REQ 0x280
#define SC_CANID_REP 0x300

#define SC_STATE_INIT 0x00
#define SC_STATE_OPERATIONAL 0x01
#define SC_STATE_ERROR 0x09

#define SC_NODE_SENSOR 0x01
#define SC_NODE_MOTOR 0x04
#define SC_NODE_BATTERY 0x07

typedef struct {
  uint32_t can_id;
  uint8_t dlc;
  uint8_t buffer[SC_MAX_DATA_LEN];
} spacecan_frame_t;

void consoleWorker(void);
bool consoleSensorModeActive(void);
bool consoleSpacecanModeActive(void);

/* ---- flatsat-lab v2: radio-reachable bus access (V-16 / V-25) ----
 * "Any process, even unprivileged, can transmit on the bus; the root
 * supervisor executes it" (Thales CYSAT 2023 demo, OPS-SAT, course ch.8.1)
 * becomes: any radio TC holder can drive the simulated CAN nodes. */
bool spacecanRadioInject(uint32_t can_id, uint8_t dlc, const uint8_t *data);
bool spacecanRadioFlood(uint8_t count);          /* arbitration-flood DoS */
bool spacecanRadioReassemblyOverflow(void);      /* finding #26 2-byte OOB */
void spacecanResetNode(uint8_t node_id);
uint8_t spacecanBusoffMask(void);                /* bit0 MOTOR bit1 BATTERY
                                                  * bit2 SENSOR */
bool spacecanCongested(void);
uint16_t spacecanLastErrCount(void);
bool spacecanBatteryChargeSync(uint8_t *pct);    /* for mission model */

#endif // FIRMWARE_SPACECAN_H
