/*  - mission.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_MISSION_H
#define FIRMWARE_MISSION_H
#include <Arduino.h>

#define FIRMWARE_PATCH 0
#define FIRMWARE_MINOR 0
#define FIRMWARE_MAJOR 1

#define MAX_PAYLOAD_CHUNK 128
#define SPACECRAFT_ID 0x01

#define SC_TM_ID_ACCE_X 0x01
#define SC_TM_ID_ACCE_Y 0x02
#define SC_TM_ID_ACCE_Z 0x03
#define SC_TM_ID_ACCE_TMP 0x04

#define SC_TM_ID_BME_TEMPERATURE 0x05
#define SC_TM_ID_BME_PRESSURE 0x06
#define SC_TM_ID_BME_ALTITUDE 0x07
#define SC_TM_ID_BME_HUMIDITY 0x08

#define SC_TM_ID_SIM_THRUSTER0 0x09
#define SC_TM_ID_SIM_THRUSTER1 0x0A

#define MISSION_MODE_SAFE 0x00
#define MISSION_MODE_NOMINAL 0x01
#define MISSION_MODE_PAYLOAD 0x02
#define MISSION_MODE_SCIENCE 0x03
#define MISSION_MODE_CONTINGENCY 0x04

#define MISSION_FLAG_BME_OK 0x01
#define MISSION_FLAG_ACC_OK 0x02
#define MISSION_FLAG_GPS_UART_OK 0x04
#define MISSION_FLAG_GPS_FIX 0x08
#define MISSION_FLAG_SECURE_LINK 0x10
#define MISSION_FLAG_PAYLOAD_ARMED 0x20
#define MISSION_FLAG_USB_DEBUG 0x40
#define MISSION_FLAG_GPS_NMEA_ACTIVE 0x80

#define GPS_STATUS_UART_OK 0x01
#define GPS_STATUS_CONNECTED 0x02
#define GPS_STATUS_NMEA_ACTIVE 0x04
#define GPS_STATUS_FIX_VALID 0x08
#define GPS_STATUS_TIME_VALID 0x10

#define GS_STATUS_MODE_ENABLED 0x01
#define GS_STATUS_GPS_VALID 0x02
#define GS_STATUS_WITHIN_RANGE 0x04
#define GS_STATUS_AUTH_ACTIVE 0x08
#define GS_STATUS_HANDSHAKE_PENDING 0x10
#define GS_STATUS_GATE_OPEN 0x20

/* APIDS TC */
// On Board Computer
#define SPP_APID_TC_PING 0x01
#define SPP_APID_TC_RESETC 0x02
#define SPP_APID_TC_SEND_FW 0x03
// EPS
#define SPP_APID_TC_SET_THRUSTER 0x04
// Communications
#define SPP_APID_TC_SET_BEACON_RATE 0x05
#define SPP_APID_TC_BROADCAST_MSG 0x06
#define SPP_APID_TC_FLASH 0x07
#define SPP_APID_TC_AES_CONFIG 0x0A
#define SPP_APID_TC_FLASH_READ 0x0B
#define SPP_APID_TC_GET_STATUS 0x0C
#define SPP_APID_TC_SET_MISSION_MODE 0x0D
#define SPP_APID_TC_GET_NAV 0x0E
#define SPP_APID_TC_GET_PAYLOAD_STATUS 0x0F
#define SPP_APID_TC_DEBUG_CONFIG 0x10
#define SPP_APID_TC_GS_MODE 0x11
#define SPP_APID_TC_GS_ACCESS 0x12
#define SPP_APID_TC_GS_STATUS 0x13
/* APIDS TM */
// On Board Computer
#define SPP_APID_TM_PING 0x01
#define SPP_APID_TM_RESETC 0x02
#define SPP_APID_TM_SEND_FW 0x03
// EPS
#define SPP_APID_TM_SET_THRUSTER 0x04
// Communications
#define SPP_APID_TM_SET_BEACON_RATE 0x05
#define SPP_APID_TM_BROADCAST_MSG 0x06
#define SPP_APID_TM_FLASH 0x07
#define SPP_APID_TM_SEND_TM 0x08
#define SPP_APID_TM_ERROR 0x09
#define SPP_APID_TM_AES_CONFIG 0x0A
#define SPP_APID_TM_FLASH_READ 0x0B
#define SPP_APID_TM_STATUS 0x0C
#define SPP_APID_TM_MISSION_MODE 0x0D
#define SPP_APID_TM_NAV 0x0E
#define SPP_APID_TM_PAYLOAD_STATUS 0x0F
#define SPP_APID_TM_DEBUG_CONFIG 0x10
#define SPP_APID_TM_GS_MODE 0x11
#define SPP_APID_TM_GS_ACCESS 0x12
#define SPP_APID_TM_GS_STATUS 0x13

/* ---- flatsat-lab v2 extension APIDs (docs/DESIGN-RATIONALE.md §5) ----
 * Extension telemetry reuses the same APID numbers, distinguished by the
 * SPP type bit (TM), like the baseline family does. */
/* APIDS TC (extension) */
#define SPP_APID_TC_GPS_OVERRIDE 0x14
#define SPP_APID_TC_SDLS_CONFIG 0x15
#define SPP_APID_TC_SDLS_OTA 0x16
#define SPP_APID_TC_KEY_VERIFY 0x17
#define SPP_APID_TC_MEMCPY 0x18
#define SPP_APID_TC_MEM_READ 0x19
#define SPP_APID_TC_SET_LOG_NAME 0x1A
#define SPP_APID_TC_SB_PUBLISH 0x1B
#define SPP_APID_TC_SC_INJECT 0x1C
#define SPP_APID_TC_FDIR_CONFIG 0x1D
#define SPP_APID_TC_SCHED 0x1E
#define SPP_APID_TC_OTA 0x1F
#define SPP_APID_TC_TC_STATS 0x20
#define SPP_APID_TC_PADDING_CONFIG 0x21
#define SPP_APID_TC_COVERT_ENQ 0x22
#define SPP_APID_TC_PAYLOAD_SNAP 0x23
#define SPP_APID_TC_HEATER 0x24
#define SPP_APID_TC_DEFENSES_CONFIG 0x25
/* flatsat-lab harness services (bench/USB bring-up of the PoCs):
 * 0x26 LAB_STATUS -- full internal state blob (info-leak by design),
 * 0x27 LAB_CTRL   -- USB-only harness bridge: radio TC injection +
 *                    emulated power cycle (scratch wipe + reboot). */
#define SPP_APID_TC_LAB_STATUS 0x26
#define SPP_APID_TM_LAB_STATUS 0x26
#define SPP_APID_TC_LAB_CTRL 0x27
#define SPP_APID_TM_LAB_CTRL 0x27
/* TEST-mode APID window accepted while FDIR safe-mode relaxations are on
 * (EX-0006.01 maintenance/test flags): */
#define SPP_APID_TEST_FIRST 0xF0
#define SPP_APID_TEST_LAST 0xFF

/* Extended status flags byte (beacon byte 10, STATUS extension) */
#define LAB_FLAG2_ANOMALY 0x01
#define LAB_FLAG2_SAFE 0x02
#define LAB_FLAG2_OTA_B 0x04
#define LAB_FLAG2_SDLS 0x08
#define LAB_FLAG2_BROWNOUT 0x10
#define LAB_FLAG2_PERSIST 0x20

/* DEFENSES_CONFIG (APID 0x25) flag bits */
#define DEF_RADIO_CRC 0x01
#define DEF_CLOAK 0x02
#define DEF_FREQ_LOCK 0x04
#define DEF_I2C_WHOAMI 0x08
#define DEF_GPS_PLAUSIBLE 0x10
#define DEF_TM_CTR 0x20
#define DEF_LOG_ENABLE 0x40
#define DEF_ANOMALY_EN 0x80

/* ---- command transport sources (moved from worker.cpp, shared by the
 * extension modules) ---- */
typedef enum {
  COMMAND_SOURCE_RADIO = 0,
  COMMAND_SOURCE_USB = 1,
} command_source_t;

#endif // FIRMWARE_MISSION_H
