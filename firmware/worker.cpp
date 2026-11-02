/*  - worker.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "hardware/watchdog.h"
#include "led.h"
#include "mission.h"
#include "rdownlink.h"
#include "ruplink.h"
#include "secure_link.h"
#include "sensors.h"
#include "sb.h"
#include "spp.h"
#include "thruster.h"
#include "usbCDC.h"
#include <Arduino.h>
#include <math.h>
#include "covert.h"
#include "cmac.h"
#include "extcmds.h"
#include "flashstore.h"
#include "labhooks.h"
#include "memserv.h"
#include "mission_model.h"
#include "sdls_sim.h"

#define CHUNK_SIZE 16

typedef struct {
  unsigned long interval;
  unsigned long previous;
} timeout_worker_t;

typedef struct {
  uint8_t mode;
  bool payloadArmed;
  bool usbDebugEnabled;
  bool groundStationModeEnabled;
  bool groundStationSessionActive;
  bool groundStationHandshakePending;
  uint16_t lastPayloadFrequency;
  uint16_t payloadForwardCount;
  uint8_t lastPayloadLength;
  uint32_t groundStationChallenge;
  unsigned long groundStationSessionExpiresMs;
  unsigned long groundStationChallengeExpiresMs;
} mission_context_t;

static const unsigned long radio_tm_interval_ms = 14000;
static const unsigned long radio_nav_interval_ms = 22000;
static const unsigned long radio_sync_interval_ms = 20000;
static const unsigned long radio_idle_interval_ms = 30000;
static const unsigned long radio_beacon_interval_ms = 18000;

const uint8_t image_data[255] = {
    0x00, 0x1F, 0x04, 0x20, 0xEB, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00,
    0x31, 0x00, 0x00, 0x00, 0x4D, 0x75, 0x01, 0x03, 0x7A, 0x00, 0xC4, 0x00,
    0x1D, 0x00, 0x00, 0x00, 0x00, 0x23, 0x02, 0x88, 0x9A, 0x42, 0x03, 0xD0,
    0x43, 0x88, 0x04, 0x30, 0x91, 0x42, 0xF7, 0xD1, 0x18, 0x1C, 0x70, 0x47,
    0x30, 0xBF, 0xFD, 0xE7, 0xF4, 0x46, 0x00, 0xF0, 0x05, 0xF8, 0xA7, 0x48,
    0x00, 0x21, 0x01, 0x60, 0x41, 0x60, 0xE7, 0x46, 0xA5, 0x48, 0x00, 0x21,
    0xC9, 0x43, 0x01, 0x60, 0x41, 0x60, 0x70, 0x47, 0xCA, 0x9B, 0x0D, 0x5B,
    0xF9, 0x1D, 0x00, 0x00, 0x28, 0x43, 0x29, 0x20, 0x32, 0x30, 0x32, 0x30,
    0x20, 0x46, 0x6F, 0x6C, 0x6C, 0x6F, 0x20, 0x54, 0x68, 0x65, 0x20, 0x57,
    0x68, 0x74, 0x65, 0x20, 0x52, 0x61, 0x62, 0x69, 0x74, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0x03, 0x4C, 0x33,
    0x57, 0x03, 0x54, 0x33, 0x8F, 0x03, 0x4D, 0x53, 0xB9, 0x26, 0x53, 0x34,
    0xAD, 0x26, 0x4D, 0x43, 0x1D, 0x26, 0x43, 0x34, 0x05, 0x26, 0x55, 0x42,
    0x91, 0x25, 0x44, 0x54, 0xA9, 0x01, 0x44, 0x45, 0xAF, 0x01, 0x57, 0x56,
    0x45, 0x01, 0x49, 0x46, 0x91, 0x24, 0x45, 0x58, 0xE5, 0x23, 0x52, 0x45,
    0x6D, 0x23, 0x52, 0x50, 0xB5, 0x23, 0x46, 0x43, 0x51, 0x23, 0x43, 0x58,
    0x21, 0x23, 0x00, 0x00, 0x47, 0x52, 0x50, 0x00, 0x43, 0x52, 0x58, 0x00,
    0x53, 0x46, 0xCC, 0x01, 0x53, 0x44, 0x4C, 0x02, 0x46, 0x5A, 0xCA, 0x01,
    0x46, 0x53, 0x34, 0x27, 0x46, 0x45, 0x28, 0x2E, 0x44, 0x53, 0x30, 0x2E,
    0x44, 0x45, 0xA4, 0x3D, 0x00, 0x00, 0x7D, 0x48, 0x01, 0x68, 0x00, 0x29,
    0x28, 0xD1, 0xFF, 0xF7, 0x9F, 0xFF, 0x7B, 0x49, 0x0A, 0x68, 0x53, 0x0E,
    0x01, 0xD3, 0x0A,
};

static const unsigned long dashboard_log_interval_ms = 5000;
static timeout_worker_t t_dashboard_log = {
    .interval = dashboard_log_interval_ms,
    .previous = 0,
};

static timeout_worker_t t_radio_tm_data = {
    .interval = radio_tm_interval_ms,
    .previous = 0,
};
static timeout_worker_t t_radio_nav = {
    .interval = radio_nav_interval_ms,
    .previous = 0,
};
static timeout_worker_t t_radio_sync = {
    .interval = radio_sync_interval_ms,
    .previous = 0,
};
static timeout_worker_t t_radio_idle = {
    .interval = radio_idle_interval_ms,
    .previous = 0,
};
static timeout_worker_t t_radio_beacon = {
    .interval = radio_beacon_interval_ms,
    .previous = 0,
};

static uint32_t image_data_len = 255;
static bool block_tx = false;
static mission_context_t mission_ctx = {
    .mode = MISSION_MODE_NOMINAL,
    .payloadArmed = false,
    .usbDebugEnabled = false,
    .groundStationModeEnabled = false,
    .groundStationSessionActive = false,
    .groundStationHandshakePending = false,
    .lastPayloadFrequency = DOWNLINK_FREQ,
    .payloadForwardCount = 0,
    .lastPayloadLength = 0,
    .groundStationChallenge = 0,
    .groundStationSessionExpiresMs = 0,
    .groundStationChallengeExpiresMs = 0,
};
static const uint8_t flash_window_id = 0xA5;
static const uint16_t flash_unlock_tag = 0xC35A;
static const uint8_t flash_read_max_bytes = 32;
static const uint8_t flash_window_blob[] __attribute__((used)) =
    "OPS:STORE_FORWARD=ENABLED\r\n"
    "OPS:PAYLOAD_WINDOW=0420Z\r\n"
    "MAINT:FLASH_WINDOW=A5:C35A\r\n"
    "FLAG=PWNSAT{flash_window_store_and_forward}\r\n";
static const uint16_t flash_window_blob_len = sizeof(flash_window_blob) - 1;
static const int32_t gs_station_lat_e7 = 361699000L;   // 36.1699 -- Las Vegas, Nevada
static const int32_t gs_station_lon_e7 = -1151398000L; // -115.1398
static const uint16_t gs_station_radius_m = 35000;
static const unsigned long gs_session_window_ms = 300000UL;
static const unsigned long gs_handshake_window_ms = 60000UL;
static const uint32_t gs_shared_auth_key = 0xC0DEFACEUL;

static void telemetrySPPTransmitAesStatus(void);
static void telemetrySPPTransmitDebugStatus(void);
static void telemetrySPPTransmitError(const char *message);
static void telemetrySPPTransmitGroundModeStatus(uint8_t requested_mode);
static void telemetrySPPTransmitGroundAccessStatus(uint8_t phase,
                                                   uint8_t auth_state);
static void telemetrySPPTransmitGroundStatus(void);
static void debugPrintTelemetryPacket(space_packet_t *space_packet,
                                      const char *route);
static int telemetrySPPBuildPacketEx(space_packet_t *space_packet, uint8_t flag,
                                     uint8_t sec_header,
                                     uint16_t sec_header_len, uint16_t apid,
                                     const uint8_t *data, uint16_t data_len,
                                     bool force_cleartext);

static uint8_t crc8_compute(const uint8_t *data, uint32_t len) {
  uint8_t crc = 0x00;

  for (uint32_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t j = 0; j < 8; j++) {
      if (crc & 0x80) {
        crc = (crc << 1) ^ 0x07;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}

static void softwareReset() { labReboot(); }

static inline int16_t float_to_fixed(float val, float scale) {
  return (int16_t)(val * scale);
}

static inline float fixed_to_float(int16_t val, float scale) {
  return ((float)val) / scale;
}

static inline uint16_t to_be16(uint16_t x) { return (x >> 8) | (x << 8); }

static void groundStationClearHandshake(void) {
  mission_ctx.groundStationHandshakePending = false;
  mission_ctx.groundStationChallenge = 0;
  mission_ctx.groundStationChallengeExpiresMs = 0;
}

static void groundStationClearSession(void) {
  mission_ctx.groundStationSessionActive = false;
  mission_ctx.groundStationSessionExpiresMs = 0;
}

static bool groundStationSessionActive(void) {
  if (!mission_ctx.groundStationSessionActive) {
    return false;
  }

  if ((long)(millis() - mission_ctx.groundStationSessionExpiresMs) >= 0) {
    Serial.println("[WARN] Ground station auth session expired");
    groundStationClearSession();
    return false;
  }

  return true;
}

static bool groundStationHandshakePending(void) {
  if (!mission_ctx.groundStationHandshakePending) {
    return false;
  }

  if ((long)(millis() - mission_ctx.groundStationChallengeExpiresMs) >= 0) {
    Serial.println("[WARN] Ground station challenge expired");
    groundStationClearHandshake();
    return false;
  }

  return true;
}

static uint16_t groundStationRemainingSeconds(unsigned long expires_ms,
                                              bool active) {
  if (!active) {
    return 0;
  }

  const unsigned long now = millis();
  const unsigned long remaining_ms = expires_ms - now;
  return (uint16_t)((remaining_ms + 999UL) / 1000UL);
}

static uint16_t groundStationSessionRemainingSeconds(void) {
  return groundStationRemainingSeconds(mission_ctx.groundStationSessionExpiresMs,
                                       groundStationSessionActive());
}

static uint16_t groundStationHandshakeRemainingSeconds(void) {
  return groundStationRemainingSeconds(
      mission_ctx.groundStationChallengeExpiresMs,
      groundStationHandshakePending());
}

static uint32_t groundStationExpectedResponse(uint32_t challenge) {
  return challenge ^ gs_shared_auth_key;
}

static uint32_t groundStationGenerateChallenge(const gps_nav_t *nav) {
  /* V-28 bench parity: seed from the ground station's last-synced mission
   * clock (labMarkLabStatusSync / 0x26 handler), which is the value the
   * ground station's own clock holds when it predicts the challenge. In
   * the simulator the ground station clock is perfectly synced with the
   * craft, so this is the same value as now_ms there. The UTC term is
   * derived from that synced clock the same way the simulator derives
   * nav["utc"] (int(now_ms/1000)%60) -- NOT from nav->utcSecond, which
   * the bench GPS fix freezes at 0 (no real NMEA) and which would break
   * the prediction by the top seed byte. */
  uint32_t seed_ms = labLastLabSyncMs();
  if (seed_ms == 0) {
    seed_ms = (uint32_t)millis(); /* cold: no status sync since boot */
  }
  uint32_t seed = (seed_ms << 1) ^ 0xA55A33CCUL;

  if (nav != NULL) {
    seed ^= (uint32_t)nav->latitudeE7;
    seed ^= ((uint32_t)nav->longitudeE7 << 7);
    seed ^= (((seed_ms / 1000) % 60) << 24);
    seed ^= ((uint32_t)nav->satellites << 16);
  }

  if (seed == 0) {
    seed = 0x13579BDFUL;
  }
  return seed;
}

static bool groundStationGpsUsable(const gps_nav_t *nav) {
  if (nav == NULL) {
    return false;
  }

  return nav->uartOk && nav->connected && nav->nmeaActive && nav->hasFix &&
         nav->latitudeE7 != 0 && nav->longitudeE7 != 0;
}

static float groundStationDistanceMetersRaw(const gps_nav_t *nav) {
  if (!groundStationGpsUsable(nav)) {
    return -1.0f;
  }

  const float lat = ((float)nav->latitudeE7) / 10000000.0f;
  const float lon = ((float)nav->longitudeE7) / 10000000.0f;
  const float gs_lat = ((float)gs_station_lat_e7) / 10000000.0f;
  const float gs_lon = ((float)gs_station_lon_e7) / 10000000.0f;

  const float lat_rad = radians(lat);
  const float lon_rad = radians(lon);
  const float gs_lat_rad = radians(gs_lat);
  const float gs_lon_rad = radians(gs_lon);
  const float x = (gs_lon_rad - lon_rad) * cosf((lat_rad + gs_lat_rad) * 0.5f);
  const float y = gs_lat_rad - lat_rad;
  return sqrtf((x * x) + (y * y)) * 6371000.0f;
}

static uint16_t groundStationDistanceReport(const gps_nav_t *nav) {
  const float distance = groundStationDistanceMetersRaw(nav);
  if (distance < 0.0f) {
    return 0xFFFF;
  }
  if (distance >= 65535.0f) {
    return 0xFFFF;
  }
  return (uint16_t)distance;
}

static bool groundStationWithinRange(const gps_nav_t *nav,
                                     uint16_t *distance_report) {
  const float distance = groundStationDistanceMetersRaw(nav);

  if (distance_report != NULL) {
    *distance_report = distance < 0.0f || distance >= 65535.0f
                           ? 0xFFFF
                           : (uint16_t)distance;
  }
  if (distance < 0.0f) {
    return false;
  }

  return distance <= (float)gs_station_radius_m;
}

static bool groundStationGateOpen(const gps_nav_t *nav) {
  if (!mission_ctx.groundStationModeEnabled) {
    return true;
  }

  return groundStationGpsUsable(nav) &&
         groundStationWithinRange(nav, NULL) && groundStationSessionActive();
}

static uint8_t groundStationStatusByte(const gps_nav_t *nav) {
  uint8_t flags = 0;

  if (mission_ctx.groundStationModeEnabled) {
    flags |= GS_STATUS_MODE_ENABLED;
  }
  if (groundStationGpsUsable(nav)) {
    flags |= GS_STATUS_GPS_VALID;
  }
  if (groundStationWithinRange(nav, NULL)) {
    flags |= GS_STATUS_WITHIN_RANGE;
  }
  if (groundStationSessionActive()) {
    flags |= GS_STATUS_AUTH_ACTIVE;
  }
  if (groundStationHandshakePending()) {
    flags |= GS_STATUS_HANDSHAKE_PENDING;
  }
  if (groundStationGateOpen(nav)) {
    flags |= GS_STATUS_GATE_OPEN;
  }

  return flags;
}

static bool groundStationCommandAllowed(space_packet_t *space_packet,
                                        command_source_t source,
                                        const char **reason) {
  const uint16_t apid = space_packet->header.identification & 0x7FF;

  if (!mission_ctx.groundStationModeEnabled) {
    return true;
  }

  if (apid == SPP_APID_TC_DEBUG_CONFIG || apid == SPP_APID_TC_GS_ACCESS) {
    return true;
  }

  /* Bench harness backdoor: the lab services are reachable from the
   * trusted local USB bus even with the ground-station gate up -- the
   * same "debug feature re-entry path" PER-0002 warns about. */
  if (source == COMMAND_SOURCE_USB &&
      (apid == SPP_APID_TC_LAB_STATUS || apid == SPP_APID_TC_LAB_CTRL)) {
    return true;
  }

  const uint16_t data_len = space_packet->header.length + 1;
  const bool gs_disable_request =
      apid == SPP_APID_TC_GS_MODE && data_len > 0 && space_packet->data[0] == 0;
  const bool gs_enable_request =
      apid == SPP_APID_TC_GS_MODE && data_len > 0 && space_packet->data[0] != 0;
  if (gs_enable_request && !mission_ctx.groundStationModeEnabled) {
    return true;
  }
  if (gs_disable_request && source == COMMAND_SOURCE_USB &&
      mission_ctx.usbDebugEnabled) {
    return true;
  }

  gps_nav_t nav = {0};
  gpsRead(&nav);

  if (!groundStationGpsUsable(&nav)) {
    if (reason != NULL) {
      *reason = "GS GPS INVALID";
    }
    return false;
  }
  if (!groundStationWithinRange(&nav, NULL)) {
    if (reason != NULL) {
      *reason = "GS RANGE LOCK";
    }
    return false;
  }
  if (!groundStationSessionActive()) {
    if (reason != NULL) {
      *reason = "GS AUTH REQUIRED";
    }
    return false;
  }

  return true;
}

static void logger_spp(space_packet_t *packet) {
  uint16_t id_raw = BE_TO_HOST16(packet->header.identification);
  uint16_t seq_raw = BE_TO_HOST16(packet->header.sequence);
  uint16_t len_raw = BE_TO_HOST16(packet->header.length);

  uint8_t type = (id_raw >> 12) & 0x01;
  uint8_t sec_hdr = (id_raw >> 11) & 0x01;
  uint16_t apid = id_raw & 0x07FF;

  uint8_t seq_flags = (seq_raw >> 14) & 0x03;
  uint16_t seq_count = seq_raw & 0x3FFF;
  Serial.printf("[%s - SPP] APID=0x%03X SEQ=%d LEN=%d FLAGS=%d SEC_HDR=%s\r\n",
                (type == SPP_PTYPE_TM) ? "TM" : "TC", apid, seq_count,
                len_raw + 1, seq_flags, sec_hdr ? "YES" : "NO");
}

static void logger_spp_tc(space_packet_t *packet) {
  uint16_t id = packet->header.identification;
  uint16_t seq = packet->header.sequence;
  uint16_t len = packet->header.length;

  uint8_t type = (id >> 12) & 0x01;
  uint8_t sec_hdr = (id >> 11) & 0x01;
  uint16_t apid = id & 0x07FF;

  uint8_t flags = (seq >> 14) & 0x03;
  uint16_t count = seq & 0x3FFF;

  /* Bench diagnostic (V-24): the console CDC is on the SAME core that
   * drains the bridge RX (core0). A backpressured console (host pump
   * momentarily busy) used to stall the whole RX path -- dropping pacer
   * frames and zeroing the anomaly TC channel. Drop the log line instead
   * of blocking the data path when the console buffer is full. */
  if (Serial.availableForWrite() < 96) {
    return;
  }
  Serial.printf("[TC - SPP] APID=0x%03X SEQ=%d LEN=%d FLAGS=%d SEC_HDR=%s\r\n",
                apid, count, len + 1, flags, sec_hdr ? "YES" : "NO");
}

static const char *packetApidName(uint16_t apid) {
  switch (apid) {
  case SPP_APID_TC_PING:
    return "PING";
  case SPP_APID_TC_RESETC:
    return "RESETC";
  case SPP_APID_TC_SEND_FW:
    return "SEND_FW";
  case SPP_APID_TC_SET_THRUSTER:
    return "SET_THRUSTER";
  case SPP_APID_TC_SET_BEACON_RATE:
    return "SET_BEACON_RATE";
  case SPP_APID_TC_BROADCAST_MSG:
    return "BROADCAST_MSG";
  case SPP_APID_TC_FLASH:
    return "FLASH";
  case SPP_APID_TM_SEND_TM:
    return "SEND_TM";
  case SPP_APID_TM_ERROR:
    return "ERROR";
  case SPP_APID_TC_AES_CONFIG:
    return "AES_CONFIG";
  case SPP_APID_TC_FLASH_READ:
    return "FLASH_READ";
  case SPP_APID_TC_GET_STATUS:
    return "STATUS";
  case SPP_APID_TC_SET_MISSION_MODE:
    return "MISSION_MODE";
  case SPP_APID_TC_GET_NAV:
    return "NAV";
  case SPP_APID_TC_GET_PAYLOAD_STATUS:
    return "PAYLOAD_STATUS";
  case SPP_APID_TC_DEBUG_CONFIG:
    return "DEBUG_CONFIG";
  case SPP_APID_TC_GS_MODE:
    return "GS_MODE";
  case SPP_APID_TC_GS_ACCESS:
    return "GS_ACCESS";
  case SPP_APID_TC_GS_STATUS:
    return "GS_STATUS";
  case SPP_APID_IDLE:
    return "IDLE";
  default:
    return "UNKNOWN";
  }
}

static void debugPrintHexDump(const uint8_t *data, size_t len) {
  if (len == 0) {
    Serial.println("(empty)");
    return;
  }

  for (size_t offset = 0; offset < len; offset += 16) {
    Serial.printf("  %04u  ", (unsigned int)offset);
    for (size_t index = 0; index < 16 && (offset + index) < len; index++) {
      Serial.printf("%02X ", data[offset + index]);
    }
    Serial.println();
  }
}

static void debugPrintSensorSnapshot(void) {
  float acc_x = 0;
  float acc_y = 0;
  float acc_z = 0;
  float acc_temp = 0;
  float bme_temp = 0;
  float bme_pressure = 0;
  float bme_altitude = 0;
  float bme_humidity = 0;
  gps_nav_t nav = {0};

  const bool acc_ok = accelerometerRead(&acc_x, &acc_y, &acc_z, &acc_temp);
  const bool bme_ok =
      bmeRead(&bme_temp, &bme_pressure, &bme_altitude, &bme_humidity);
  const bool gps_uart_ok = gpsRead(&nav);
  const uint8_t gps_status = gpsStatusByte(&nav);
  const uint8_t gs_status = groundStationStatusByte(&nav);
  const uint16_t gs_distance = groundStationDistanceReport(&nav);
  const uint16_t gs_session_s = groundStationSessionRemainingSeconds();
  const uint16_t gs_challenge_s = groundStationHandshakeRemainingSeconds();

  Serial.println("[DEBUG TX][SENSORS]");
  Serial.printf("  ACC: ok=%s x=%.2f y=%.2f z=%.2f temp=%.2f\r\n",
                acc_ok ? "yes" : "no", acc_x, acc_y, acc_z, acc_temp);
  Serial.printf("  BME: ok=%s temp=%.2f pressure=%.2f altitude=%.2f humidity=%.2f\r\n",
                bme_ok ? "yes" : "no", bme_temp, bme_pressure, bme_altitude,
                bme_humidity);
  Serial.printf(
      "  GPS: uart=%s connected=%s nmea=%s fix=%s time=%s status=0x%02X sats=%u lat_e7=%ld lon_e7=%ld alt_cm=%ld\r\n",
      gps_uart_ok ? "yes" : "no", nav.connected ? "yes" : "no",
      nav.nmeaActive ? "yes" : "no", nav.hasFix ? "yes" : "no",
      nav.hasDateTime ? "yes" : "no", gps_status, nav.satellites,
      (long)nav.latitudeE7, (long)nav.longitudeE7, (long)nav.altitudeCm);
  Serial.printf("  GPS UTC: %04u-%02u-%02u %02u:%02u:%02uZ\r\n", nav.utcYear,
                nav.utcMonth, nav.utcDay, nav.utcHour, nav.utcMinute,
                nav.utcSecond);
  Serial.printf(
      "  MISSION: mode=%u payload_armed=%s secure_link=%s usb_debug=%s beacon_s=%lu\r\n",
      mission_ctx.mode, mission_ctx.payloadArmed ? "yes" : "no",
      secureLinkIsEnabled() ? "yes" : "no",
      mission_ctx.usbDebugEnabled ? "yes" : "no",
      t_radio_beacon.interval / 1000);
  Serial.printf(
      "  GS: mode=%s auth=%s challenge_pending=%s status=0x%02X distance_m=%u session_s=%u challenge_s=%u challenge=0x%08lX radius_m=%u gate=%s\r\n",
      mission_ctx.groundStationModeEnabled ? "yes" : "no",
      groundStationSessionActive() ? "yes" : "no",
      groundStationHandshakePending() ? "yes" : "no", gs_status, gs_distance,
      gs_session_s, gs_challenge_s, (unsigned long)mission_ctx.groundStationChallenge,
      gs_station_radius_m, groundStationGateOpen(&nav) ? "open" : "closed");
}

static void debugPrintTelemetryPacket(space_packet_t *space_packet,
                                      const char *route) {
  if (!mission_ctx.usbDebugEnabled) {
    return;
  }

  const uint16_t id_raw = BE_TO_HOST16(space_packet->header.identification);
  const uint16_t seq_raw = BE_TO_HOST16(space_packet->header.sequence);
  const uint16_t len_raw = BE_TO_HOST16(space_packet->header.length);
  const uint16_t apid = id_raw & 0x07FF;
  const uint16_t payload_len = len_raw + 1;

  Serial.println("=========== DEBUG TX PACKET ===========");
  Serial.printf("Route:                %s\r\n", route);
  Serial.printf("APID:                 0x%03X (%s)\r\n", apid,
                packetApidName(apid));
  Serial.printf("Sequence Flags:       %u\r\n", (seq_raw >> 14) & 0x03);
  Serial.printf("Sequence Count:       %u\r\n", seq_raw & 0x3FFF);
  Serial.printf("Data Field Size:      %u\r\n", payload_len);
  Serial.printf("Cleartext Debug:      yes\r\n");
  Serial.println();
  Serial.println("[PAYLOAD]");
  debugPrintHexDump(space_packet->data, payload_len);
  Serial.println();
  debugPrintSensorSnapshot();
  Serial.println("=======================================");
}

static void transmitPacketRadioUSB(uint8_t *buffer, ssize_t buffer_len) {
  obcUSBTransmitFrame(buffer, buffer_len);
  downlinkRadioTransmitNBlock(buffer, buffer_len);
}

static bool transmitPacketRadioUSBBlock(uint8_t *buffer, ssize_t buffer_len) {
  obcUSBTransmitFrame(buffer, buffer_len);
  return downlinkRadioTransmit(buffer, buffer_len);
}

static uint16_t packetTotalLen(space_packet_t *space_packet) {
  return SPP_PRIMARY_HEADER_LEN +
         (HOST_TO_BE16(space_packet->header.length) + 1);
}

static bool dispatchTelemetryPacket(space_packet_t *space_packet, bool blocking) {
  const uint16_t total_len = packetTotalLen(space_packet);
  if (blocking) {
    if (!transmitPacketRadioUSBBlock((uint8_t *)space_packet, total_len)) {
      return false;
    }
  } else {
    transmitPacketRadioUSB((uint8_t *)space_packet, total_len);
  }
  debugPrintTelemetryPacket(space_packet, blocking ? "USB+RADIO(BLOCK)" : "USB+RADIO");
  logger_spp(space_packet);
  return true;
}

static int telemetrySPPBuildPacketEx(space_packet_t *space_packet, uint8_t flag,
                                     uint8_t sec_header,
                                     uint16_t sec_header_len, uint16_t apid,
                                     const uint8_t *data, uint16_t data_len,
                                     bool force_cleartext) {
  uint8_t secure_buffer[SPP_MAX_PAYLOAD_CHUNK] = {0};
  uint16_t secure_len = data_len;
  const uint8_t *packet_data = data;
  const bool bypass_secure_link = mission_ctx.usbDebugEnabled || force_cleartext;

  /* DEF_TM_CTR (V-11 substrate): when the operator upgrades the downlink
   * to AES-128-CTR under the SA-0 key, the counter block is just the TM
   * sequence number -- trivially re-used after any reset, which is the
   * keystream-reuse hole the KEY_VERIFY oracle exploits.  The reference
   * model applies this to EVERY TM (base family + lab extensions), so
   * the decision lives in the common builder, not only in labTmSend():
   * before the fix the 0x0C status / periodic TMs stayed on the ECB
   * path on silicon and the "CTR everywhere" defense was a lie.  The
   * counter value is exactly what spp_tm_build_packet() stamps as the
   * frame sequence (peek == (tm+1) == seq after tm++). */
  if (!bypass_secure_link && secureLinkIsEnabled() &&
      labDefenseBit(DEF_TM_CTR)) {
    if (data_len > SPP_MAX_PAYLOAD_CHUNK - 2) {
      return SPP_ERROR_PAYLOAD_LEN_OUT_LIMITS;
    }
    secure_len = (uint16_t)(((uint16_t)(data_len + 2) + 15u) & (uint16_t)~0x0F);
    secure_buffer[0] = (uint8_t)(data_len >> 8);
    secure_buffer[1] = (uint8_t)(data_len & 0xFF);
    memcpy(secure_buffer + 2, data, data_len);
    const uint16_t ctr_val = sppTmCounterPeek();
    uint8_t ctr_block[16] = {0};
    ctr_block[12] = (uint8_t)(ctr_val >> 24);
    ctr_block[13] = (uint8_t)(ctr_val >> 16);
    ctr_block[14] = (uint8_t)(ctr_val >> 8);
    ctr_block[15] = (uint8_t)ctr_val;
    labCtrXor(sdlsGetSa(0)->key, ctr_block, secure_buffer, secure_buffer,
              secure_len);
    packet_data = secure_buffer;
    force_cleartext = true;  /* already encrypted: skip the ECB wrap below */
  } else if (secureLinkIsEnabled() && !bypass_secure_link) {
    if (!secureLinkEncodePayload(data, data_len, secure_buffer, &secure_len)) {
      return SPP_ERROR_PAYLOAD_LEN_OUT_LIMITS;
    }
    packet_data = secure_buffer;
  }

  memset(space_packet, 0, sizeof(space_packet_t));
  return spp_tm_build_packet(space_packet, flag, sec_header, sec_header_len,
                             apid, packet_data, secure_len);
}

static int telemetrySPPBuildPacket(space_packet_t *space_packet, uint8_t flag,
                                   uint8_t sec_header,
                                   uint16_t sec_header_len, uint16_t apid,
                                   const uint8_t *data, uint16_t data_len) {
  return telemetrySPPBuildPacketEx(space_packet, flag, sec_header, sec_header_len,
                                   apid, data, data_len, false);
}

static bool secureLinkDecodeInPlace(space_packet_t *space_packet,
                                    command_source_t source) {
  if (!secureLinkIsEnabled()) {
    return true;
  }

  if (source == COMMAND_SOURCE_USB && mission_ctx.usbDebugEnabled) {
    return true;
  }

  /* PER-0002 bench transport: the lab services (LAB_STATUS / LAB_CTRL)
   * carry their own framing (inner TC frames, control bodies) and are
   * parsed in the clear, exactly like flatsat_sim.py :: _handle does for
   * apid 0x26 / 0x27. AES belongs to the INNER frame that LAB_CTRL sub-1
   * re-injects into the radio pipeline -- which then does get the full
   * secure-link treatment. */
  if (source == COMMAND_SOURCE_USB) {
    const uint16_t lab_apid = space_packet->header.identification & 0x7FF;
    if (lab_apid == SPP_APID_TC_LAB_STATUS || lab_apid == SPP_APID_TC_LAB_CTRL) {
      return true;
    }
  }

  const uint16_t cipher_len = space_packet->header.length + 1;
  uint8_t plain_buffer[SPP_MAX_PAYLOAD_CHUNK] = {0};
  uint16_t plain_len = 0;

  if (!secureLinkDecodePayload(space_packet->data, cipher_len, plain_buffer,
                               &plain_len)) {
    return false;
  }

  memset(space_packet->data, 0, sizeof(space_packet->data));
  if (plain_len > 0) {
    memcpy(space_packet->data, plain_buffer, plain_len);
  }
  /* The SPP length field is payload_len - 1, so a truly empty plaintext has
   * no representable value. The 0xFFFF sentinel makes the PL macro
   * ((uint16_t)(length + 1)) fold to 0, so handlers observe a genuine
   * zero-length payload instead of a phantom 1-byte frame (which would e.g.
   * enqueue a spurious byte into the covert FIFO for an empty 0x22). This
   * mirrors flatsat_sim.py, where the decoded empty plaintext is passed to
   * the dispatch as a 0-byte payload. Downstream consumers only read the
   * length through PL / (uint8_t)(length + 1), both of which wrap 0xFFFF to
   * 0; a 1-byte plaintext still encodes as length 0 (PL 1) and is unchanged. */
  space_packet->header.length =
      (plain_len == 0) ? 0xFFFF : (uint16_t)(plain_len - 1);
  return true;
}

static bool extractToggleConfigMode(space_packet_t *space_packet,
                                    bool *new_state) {
  if (new_state == NULL) {
    return false;
  }

  const uint16_t data_len = space_packet->header.length + 1;
  if (data_len == 0) {
    return false;
  }

  uint8_t plain_buffer[SPP_MAX_PAYLOAD_CHUNK] = {0};
  uint16_t plain_len = 0;
  if ((data_len % 16) == 0 &&
      secureLinkDecodePayload(space_packet->data, data_len, plain_buffer,
                              &plain_len) &&
      plain_len > 0) {
    *new_state = plain_buffer[0] != 0;
    return true;
  }

  *new_state = space_packet->data[0] != 0;
  return true;
}

static void commandAesConfigHandler(bool new_state) {
  secureLinkSetEnabled(new_state);
  Serial.printf("[INFO] Secure link %s\r\n",
                secureLinkIsEnabled() ? "enabled" : "disabled");
  telemetrySPPTransmitAesStatus();
}

static void commandDebugConfigHandler(bool new_state) {
  mission_ctx.usbDebugEnabled = new_state;
  Serial.printf("[INFO] USB debug mode %s\r\n",
                mission_ctx.usbDebugEnabled ? "enabled" : "disabled");
  telemetrySPPTransmitDebugStatus();
}

static bool missionModePayloadArmed(uint8_t mode) {
  return mode == MISSION_MODE_PAYLOAD || mode == MISSION_MODE_SCIENCE;
}

static uint8_t missionStatusFlags(void) {
  uint8_t flags = sensorsStatusFlags();
  /* V-17/V-26 bench parity: the SB sensor-enable mask (MID 0x103) is the
   * operator's PRESENCE view -- writing it from the bus silences the
   * BME/ACC present-flags exactly like the reference model
   * (flatsat_sim.py _flags() reads sensor_mask, not live I2C health). */
  flags &= (uint8_t)(0xFC | sbSensorMask());
  if (secureLinkIsEnabled()) {
    flags |= MISSION_FLAG_SECURE_LINK;
  }
  if (mission_ctx.payloadArmed) {
    flags |= MISSION_FLAG_PAYLOAD_ARMED;
  }
  if (mission_ctx.usbDebugEnabled) {
    flags |= MISSION_FLAG_USB_DEBUG;
  }
  return flags;
}

static void missionApplyMode(uint8_t mode) {
  mission_ctx.mode = mode;
  mission_ctx.payloadArmed = missionModePayloadArmed(mode);

  if (mode == MISSION_MODE_SAFE || mode == MISSION_MODE_CONTINGENCY) {
    thrusterSetT0Power(0);
    thrusterSetT1Power(0);
  }
}

static void commandGroundStationModeHandler(space_packet_t *space_packet,
                                            command_source_t source) {
  const uint16_t data_len = space_packet->header.length + 1;
  gps_nav_t nav = {0};
  gpsRead(&nav);

  if (data_len == 0) {
    telemetrySPPTransmitError("GS MODE FORMAT");
    telemetrySPPTransmitGroundModeStatus(0);
    return;
  }

  const uint8_t requested_mode = space_packet->data[0] != 0 ? 0x01 : 0x00;
  if (requested_mode == 0x00) {
    if (mission_ctx.groundStationModeEnabled &&
        !(groundStationGateOpen(&nav) ||
          (source == COMMAND_SOURCE_USB && mission_ctx.usbDebugEnabled))) {
      telemetrySPPTransmitError("GS DISABLE AUTH");
      telemetrySPPTransmitGroundModeStatus(requested_mode);
      return;
    }

    mission_ctx.groundStationModeEnabled = false;
    groundStationClearSession();
    groundStationClearHandshake();
    Serial.println("[INFO] Ground station communication mode disabled");
    telemetrySPPTransmitGroundModeStatus(requested_mode);
    return;
  }

  if (!groundStationGpsUsable(&nav)) {
    telemetrySPPTransmitError("GS MODE GPS REQUIRED");
    telemetrySPPTransmitGroundModeStatus(requested_mode);
    return;
  }
  if (!groundStationWithinRange(&nav, NULL)) {
    telemetrySPPTransmitError("GS RANGE LOCK");
    telemetrySPPTransmitGroundModeStatus(requested_mode);
    return;
  }

  mission_ctx.groundStationModeEnabled = true;
  Serial.println("[INFO] Ground station communication mode enabled");
  telemetrySPPTransmitGroundModeStatus(requested_mode);
}

static void commandGroundStationAccessHandler(space_packet_t *space_packet) {
  const uint16_t data_len = space_packet->header.length + 1;
  gps_nav_t nav = {0};
  gpsRead(&nav);

  if (data_len == 0) {
    telemetrySPPTransmitError("GS ACCESS FORMAT");
    telemetrySPPTransmitGroundAccessStatus(0xFF, 0x02);
    return;
  }

  if (!groundStationGpsUsable(&nav)) {
    telemetrySPPTransmitError("GS ACCESS GPS");
    telemetrySPPTransmitGroundAccessStatus(space_packet->data[0], 0x02);
    return;
  }
  if (!groundStationWithinRange(&nav, NULL)) {
    telemetrySPPTransmitError("GS RANGE LOCK");
    telemetrySPPTransmitGroundAccessStatus(space_packet->data[0], 0x02);
    return;
  }

  const uint8_t phase = space_packet->data[0];
  if (phase == 0x00) {
    mission_ctx.groundStationChallenge = groundStationGenerateChallenge(&nav);
    labLeakWrite((const uint8_t *)&mission_ctx.groundStationChallenge, 4);
    mission_ctx.groundStationHandshakePending = true;
    mission_ctx.groundStationChallengeExpiresMs =
        millis() + gs_handshake_window_ms;
    Serial.printf("[INFO] Ground station challenge issued: 0x%08lX\r\n",
                  (unsigned long)mission_ctx.groundStationChallenge);
    telemetrySPPTransmitGroundAccessStatus(phase, 0x00);
    return;
  }
  if (phase != 0x01 || data_len < 5) {
    telemetrySPPTransmitError("GS ACCESS FORMAT");
    telemetrySPPTransmitGroundAccessStatus(phase, 0x02);
    return;
  }
  if (!groundStationHandshakePending()) {
    telemetrySPPTransmitError("GS CHALLENGE NONE");
    telemetrySPPTransmitGroundAccessStatus(phase, 0x03);
    return;
  }

  const uint32_t response = ((uint32_t)space_packet->data[1] << 24) |
                            ((uint32_t)space_packet->data[2] << 16) |
                            ((uint32_t)space_packet->data[3] << 8) |
                            (uint32_t)space_packet->data[4];
  const uint32_t expected =
      groundStationExpectedResponse(mission_ctx.groundStationChallenge);

  if (response != expected) {
    Serial.printf("[WARN] Ground station handshake failed: resp=0x%08lX expected=0x%08lX\r\n",
                  (unsigned long)response, (unsigned long)expected);
    groundStationClearHandshake();
    groundStationClearSession();
    telemetrySPPTransmitError("GS AUTH FAIL");
    telemetrySPPTransmitGroundAccessStatus(phase, 0x02);
    return;
  }

  mission_ctx.groundStationSessionActive = true;
  mission_ctx.groundStationSessionExpiresMs = millis() + gs_session_window_ms;
  groundStationClearHandshake();
  Serial.println("[INFO] Ground station handshake accepted");
  telemetrySPPTransmitGroundAccessStatus(phase, 0x01);
}

static void bufferPackU16LE(uint8_t *buffer, int *offset, uint16_t value) {
  buffer[(*offset)++] = (uint8_t)(value & 0xFF);
  buffer[(*offset)++] = (uint8_t)((value >> 8) & 0xFF);
}

static void bufferPackU32LE(uint8_t *buffer, int *offset, uint32_t value) {
  buffer[(*offset)++] = (uint8_t)(value & 0xFF);
  buffer[(*offset)++] = (uint8_t)((value >> 8) & 0xFF);
  buffer[(*offset)++] = (uint8_t)((value >> 16) & 0xFF);
  buffer[(*offset)++] = (uint8_t)((value >> 24) & 0xFF);
}

static void bufferPackI32LE(uint8_t *buffer, int *offset, int32_t value) {
  bufferPackU32LE(buffer, offset, (uint32_t)value);
}

static void bufferPackFixedFloat(uint8_t *buffer, int *offset, float value) {
  const int16_t fixed = float_to_fixed(value, 100.0f);
  bufferPackU16LE(buffer, offset, (uint16_t)fixed);
}

static void telemetrySPPPackFillFloatToBuffer(uint8_t *buffer, int *offset,
                                              float metric) {
  int16_t val = float_to_fixed(metric, 100.0f);

  buffer[(*offset)++] = (uint8_t)(val & 0xFF);        // LSB
  buffer[(*offset)++] = (uint8_t)((val >> 8) & 0xFF); // MSB
}

static void telemetrySPPPackFrame(float x, float y, float z, float t, float tm,
                                  float p, float alt, float hum) {
  int offset = 0;
  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  buffer[offset++] = SPACECRAFT_ID;
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, x);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, y);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, z);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, t);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, tm);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, p);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, alt);
  telemetrySPPPackFillFloatToBuffer(buffer, &offset, hum);
  buffer[offset++] = thrusterGetT0Power();
  buffer[offset++] = thrusterGetT1Power();
  buffer[offset++] = '\0';

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_SEND_TM, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitVersion(void) {
  int offset = 0;
  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = FIRMWARE_PATCH;
  buffer[offset++] = FIRMWARE_MINOR;
  buffer[offset++] = FIRMWARE_MAJOR;
  buffer[offset++] = '\0';

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_SEND_FW, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);

    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitPingSync(void) {
  uint8_t buffer[8] = {SPACECRAFT_ID, 0x50, 0x77, 0x6e, 0x73, 0x61, 0x74, 0x00};

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_PING, buffer, 8);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitIDLE(void) {
  uint8_t idle_buffer[14] = {0x48, 0x61, 0x63, 0x6b, 0x54, 0x68, 0x65,
                             0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00};
  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_IDLE, idle_buffer, sizeof(idle_buffer));
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitPingAck(void) {
  uint8_t buffer[5] = {SPACECRAFT_ID, 0x41, 0x43, 0x4b, 0x00};

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_PING, buffer, 5);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

// Secured-format PING ACK: same payload as telemetrySPPTransmitPingAck(),
// built with a secondary header (a plain 4-byte counter, echoed back from
// the request) via spp_tm_build_packet_secured(). Deliberately always
// cleartext -- this pass only implements the CCSDS secondary-header
// structure, not the crypto/security part (no IV, no freshness check), so
// it stays independent of secure_link's on/off state rather than half-wire
// it into a decrypt path that was never designed around a header offset.
// See the matching bypass in commandHandlerInternal() for the receive side.
static void telemetrySPPTransmitPingAckSecured(uint32_t counter) {
  uint8_t buffer[5] = {SPACECRAFT_ID, 0x41, 0x43, 0x4b, 0x00};

  space_packet_t tm_packet;
  const int ret = spp_tm_build_packet_secured(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_APID_TM_PING, counter,
      buffer, sizeof(buffer));
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame (secured): ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitBeacon(void) {
  /* flatsat-lab v2: the chatty beacon (REC-0001/REC-0003). 8-byte magic
   * preserved for tooling compatibility, then a 13-byte status core
   * [mode | flags1 | flags2 | bus_v_lo | bus_v_hi | tilt_lo | tilt_hi |
   *  gs/eclipse | millis BE32 | boot_count], padded to 64 bytes by the
   * covert policy (padding_mode 1 = raw RAM leak, 2 = covert FIFO).
   * CM0006 cloak (DEF_CLOAK) zeroes the status core but keeps the magic. */
  mission_model_t mm;
  missionModelGet(&mm);
  gps_nav_t nav = {0};
  gpsRead(&nav);

  uint8_t buffer[COVERT_PAD_TARGET];
  memset(buffer, 0, sizeof(buffer));
  buffer[0] = SPACECRAFT_ID;
  buffer[1] = 0x42; /* B e a c o n 0 */
  buffer[2] = 0x65;
  buffer[3] = 0x61;
  buffer[4] = 0x63;
  buffer[5] = 0x6f;
  buffer[6] = 0x6e;
  buffer[7] = 0x00;

  const uint8_t gs_bits = (uint8_t)(groundStationStatusByte(&nav) & 0x0F);
  buffer[8] = mission_ctx.mode;
  buffer[9] = missionStatusFlags();
  buffer[10] = labExtFlags();
  const uint16_t bus_v = (uint16_t)(mm.bus_voltage * 100.0f);
  buffer[11] = (uint8_t)(bus_v & 0xFF);
  buffer[12] = (uint8_t)(bus_v >> 8);
  uint32_t tilt_q = (uint32_t)(mm.tilt_dps * 100.0f);
  if (tilt_q > 0xFFFFu) {
    tilt_q = 0xFFFFu;
  }
  buffer[13] = (uint8_t)(tilt_q & 0xFF);
  buffer[14] = (uint8_t)(tilt_q >> 8);
  buffer[15] = (uint8_t)(gs_bits | (mm.eclipse ? 0x10 : 0));
  const uint32_t ms = millis();
  buffer[16] = (uint8_t)(ms >> 24);
  buffer[17] = (uint8_t)(ms >> 16);
  buffer[18] = (uint8_t)(ms >> 8);
  buffer[19] = (uint8_t)ms;
  buffer[20] = (uint8_t)labBootCount();
  if (labBeaconCloaked()) {
    memset(&buffer[8], 0, 13); /* CM0006 cloak */
  }
  covertApplyPadding(buffer, 21, COVERT_PAD_TARGET);

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_PING, buffer, COVERT_PAD_TARGET);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitError(const char *message) {
  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  size_t message_len = strnlen(message, MAX_PAYLOAD_CHUNK - 1);
  memcpy(buffer, message, message_len);
  buffer[message_len++] = '\0';

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_ERROR, buffer, (uint16_t)message_len);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitAesStatus(void) {
  uint8_t buffer[3] = {SPACECRAFT_ID,
                       (uint8_t)(secureLinkIsEnabled() ? 0x01 : 0x00), 0x00};

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_AES_CONFIG, buffer, sizeof(buffer));
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitDebugStatus(void) {
  uint8_t buffer[4] = {SPACECRAFT_ID,
                       (uint8_t)(mission_ctx.usbDebugEnabled ? 0x01 : 0x00),
                       (uint8_t)(secureLinkIsEnabled() ? 0x01 : 0x00), 0x01};

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacketEx(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_DEBUG_CONFIG, buffer, sizeof(buffer), true);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitGroundModeStatus(uint8_t requested_mode) {
  gps_nav_t nav = {0};
  gpsRead(&nav);

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = requested_mode;
  buffer[offset++] = (uint8_t)(mission_ctx.groundStationModeEnabled ? 0x01 : 0x00);
  buffer[offset++] = groundStationStatusByte(&nav);
  buffer[offset++] = gpsStatusByte(&nav);
  bufferPackU16LE(buffer, &offset, groundStationSessionRemainingSeconds());
  bufferPackU16LE(buffer, &offset, groundStationHandshakeRemainingSeconds());

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_GS_MODE, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitGroundAccessStatus(uint8_t phase,
                                                   uint8_t auth_state) {
  gps_nav_t nav = {0};
  gpsRead(&nav);

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = phase;
  buffer[offset++] = auth_state;
  buffer[offset++] = groundStationStatusByte(&nav);
  buffer[offset++] = gpsStatusByte(&nav);
  bufferPackU32LE(buffer, &offset, mission_ctx.groundStationChallenge);
  bufferPackU16LE(buffer, &offset, groundStationSessionRemainingSeconds());
  bufferPackU16LE(buffer, &offset, groundStationHandshakeRemainingSeconds());

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_GS_ACCESS, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitGroundStatus(void) {
  gps_nav_t nav = {0};
  gpsRead(&nav);

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = groundStationStatusByte(&nav);
  buffer[offset++] = gpsStatusByte(&nav);
  bufferPackU16LE(buffer, &offset, groundStationDistanceReport(&nav));
  bufferPackU16LE(buffer, &offset, groundStationSessionRemainingSeconds());
  bufferPackU32LE(buffer, &offset, mission_ctx.groundStationChallenge);
  bufferPackU16LE(buffer, &offset, groundStationHandshakeRemainingSeconds());
  bufferPackI32LE(buffer, &offset, gs_station_lat_e7);
  bufferPackI32LE(buffer, &offset, gs_station_lon_e7);
  bufferPackU16LE(buffer, &offset, gs_station_radius_m);

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_GS_STATUS, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

/* Declared later in this file / in anomaly.h, fdir.h (included from the
 * lab-hooks section below) -- needed for the 0x0C flags2 byte. */
bool anomalyAlarmActive(void);
bool fdirSafeActive(void);
bool labPersistentCookiePresent(void);

static void telemetrySPPTransmitMissionStatus(void) {
  gps_nav_t nav = {0};
  gpsRead(&nav);
  const uint8_t gps_status = gpsStatusByte(&nav);

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = mission_ctx.mode;
  buffer[offset++] = missionStatusFlags();
  buffer[offset++] = gps_status;
  buffer[offset++] = (uint8_t)(t_radio_beacon.interval / 1000);
  buffer[offset++] = thrusterGetT0Power();
  buffer[offset++] = thrusterGetT1Power();
  buffer[offset++] = nav.satellites;
  /* V-31/V-32 bench parity: expose the shared forward counter (covertVcc),
   * which both broadcast and snap bump -- matching the simulator's single
   * self.vcc field at this offset. */
  bufferPackU16LE(buffer, &offset, covertVcc());
  bufferPackU16LE(buffer, &offset, mission_ctx.lastPayloadFrequency);
  bufferPackU32LE(buffer, &offset, millis() / 1000);
  buffer[offset++] = nav.utcHour;
  buffer[offset++] = nav.utcMinute;
  buffer[offset++] = nav.utcSecond;
  buffer[offset++] = nav.utcDay;
  buffer[offset++] = nav.utcMonth;
  bufferPackU16LE(buffer, &offset, nav.utcYear);
  buffer[offset++] = FIRMWARE_PATCH;
  buffer[offset++] = FIRMWARE_MINOR;
  buffer[offset++] = FIRMWARE_MAJOR;
  /* v2 extension byte (bench parity with the simulator's _flags2(): the
   * 27th byte of the 0x0C payload). The board used to end at 26 bytes,
   * so V-21/V-34 PoCs that read the trailing PERSIST bit (0x20) saw the
   * FIRMWARE_MAJOR byte instead. Bit layout: ANOMALY 0x01, SAFE 0x02,
   * OTA_B 0x04, SDLS 0x08, BROWNOUT 0x10, PERSIST 0x20. */
  {
    fs_ota_status_t ota_st;
    otaGetStatus(&ota_st);
    mission_model_t mm_st;
    missionModelGet(&mm_st);
    uint8_t f2 = 0;
    if (anomalyAlarmActive()) {
      f2 |= 0x01;
    }
    if (fdirSafeActive()) {
      f2 |= 0x02;
    }
    if (ota_st.booted_slot == 1) {
      f2 |= 0x04;
    }
    if (sdlsIsEnabled()) {
      f2 |= 0x08;
    }
    if (mm_st.brownout_armed) {
      f2 |= 0x10;
    }
    if (labPersistentCookiePresent()) {
      f2 |= 0x20;
    }
    buffer[offset++] = f2;
  }

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_STATUS, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitMissionMode(void) {
  uint8_t buffer[4] = {SPACECRAFT_ID, mission_ctx.mode,
                       (uint8_t)(mission_ctx.payloadArmed ? 0x01 : 0x00),
                       missionStatusFlags()};

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_MISSION_MODE, buffer, sizeof(buffer));
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitPayloadStatus(void) {
  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = mission_ctx.mode;
  buffer[offset++] = (uint8_t)(mission_ctx.payloadArmed ? 0x01 : 0x00);
  buffer[offset++] = (uint8_t)(secureLinkIsEnabled() ? 0x01 : 0x00);
  bufferPackU16LE(buffer, &offset, mission_ctx.lastPayloadFrequency);
  bufferPackU16LE(buffer, &offset, covertVcc());
  buffer[offset++] = mission_ctx.lastPayloadLength;
  buffer[offset++] = 0x00;

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_PAYLOAD_STATUS, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitNavSnapshot(void) {
  gps_nav_t nav = {0};
  gpsRead(&nav);
  const uint8_t gps_status = gpsStatusByte(&nav);

  float x = 0;
  float y = 0;
  float z = 0;
  float t = 0;
  accelerometerRead(&x, &y, &z, &t);

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  int offset = 0;
  buffer[offset++] = SPACECRAFT_ID;
  buffer[offset++] = gps_status;
  buffer[offset++] = nav.satellites;
  bufferPackI32LE(buffer, &offset, nav.latitudeE7);
  bufferPackI32LE(buffer, &offset, nav.longitudeE7);
  bufferPackI32LE(buffer, &offset, nav.altitudeCm);
  buffer[offset++] = nav.utcHour;
  buffer[offset++] = nav.utcMinute;
  buffer[offset++] = nav.utcSecond;
  buffer[offset++] = nav.utcDay;
  buffer[offset++] = nav.utcMonth;
  bufferPackU16LE(buffer, &offset, nav.utcYear);
  bufferPackFixedFloat(buffer, &offset, x);
  bufferPackFixedFloat(buffer, &offset, y);
  bufferPackFixedFloat(buffer, &offset, z);
  bufferPackFixedFloat(buffer, &offset, t);

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_NAV, buffer, offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitFlashRead(uint16_t offset, uint8_t read_len) {
  if (read_len == 0) {
    telemetrySPPTransmitError("FLASH READ SIZE ZERO");
    return;
  }
  if (offset >= flash_window_blob_len) {
    telemetrySPPTransmitError("FLASH READ OOB");
    return;
  }

  const uint8_t bounded_len =
      read_len > flash_read_max_bytes ? flash_read_max_bytes : read_len;
  const uint16_t available = flash_window_blob_len - offset;
  const uint8_t copy_len =
      bounded_len > available ? (uint8_t)available : bounded_len;

  uint8_t buffer[MAX_PAYLOAD_CHUNK] = {0};
  uint16_t buff_offset = 0;
  buffer[buff_offset++] = SPACECRAFT_ID;
  buffer[buff_offset++] = (uint8_t)(offset & 0xFF);
  buffer[buff_offset++] = (uint8_t)((offset >> 8) & 0xFF);
  buffer[buff_offset++] = copy_len;
  memcpy(&buffer[buff_offset], &flash_window_blob[offset], copy_len);
  buff_offset += copy_len;
  buffer[buff_offset++] = crc8_compute(&flash_window_blob[offset], copy_len);

  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacket(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      SPP_APID_TM_FLASH_READ, buffer, buff_offset);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
    Serial.println(ret);
    ledBlink(8, LED_COLOR_RED);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

static void telemetrySPPTransmitFlash(void) {
  block_tx = true;
  const uint32_t total_chunks = (image_data_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

  for (uint32_t i = 0; i < total_chunks; i++) {
    uint32_t offset = i * CHUNK_SIZE;
    uint32_t remaining = image_data_len - offset;
    uint32_t size = (remaining >= CHUNK_SIZE) ? CHUNK_SIZE : remaining;

    uint8_t buffer[MAX_PAYLOAD_CHUNK];
    uint16_t buff_offset = 0;

    memset(buffer, 0, sizeof(buffer));

    buffer[buff_offset++] = SPACECRAFT_ID;

    /* Ancillary Data Field */
    // Packet Index
    buffer[buff_offset++] = (uint8_t)(i & 0xFF);
    buffer[buff_offset++] = (uint8_t)((i >> 8) & 0xFF);
    // Offset
    buffer[buff_offset++] = (uint8_t)(offset & 0xFF);
    buffer[buff_offset++] = (uint8_t)((offset >> 8) & 0xFF);
    // Remaining
    buffer[buff_offset++] = (uint8_t)(remaining & 0xFF);
    buffer[buff_offset++] = (uint8_t)((remaining >> 8) & 0xFF);

    if (buff_offset + size + 1 > MAX_PAYLOAD_CHUNK) {
      Serial.println("[ERROR] Payload overflow");
      block_tx = false;
      return;
    }

    // Data
    memcpy(&buffer[buff_offset], &image_data[offset], size);
    buff_offset += size;

    // CRC
    buffer[buff_offset++] = crc8_compute(&image_data[offset], size);

    space_packet_t tm_packet;
    const uint8_t flag = i == 0                    ? SPP_GROUP_FLAG_START
                         : (i == total_chunks - 1) ? SPP_GROUP_FLAG_END
                                                   : SPP_GROUP_FLAG_CONT;
    int ret =
        telemetrySPPBuildPacket(&tm_packet, flag, SPP_SECHEAD_FLAG_NOPRESENT, 0,
                                SPP_APID_TM_FLASH, buffer, buff_offset);
    if (ret != SPP_ERROR_NONE) {
      Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
      Serial.println(ret);
      ledBlink(8, LED_COLOR_RED);
      block_tx = false;
      return;
    }

    /* V-37 bench parity: non-blocking dispatch. The blocking radio TX
     * (downlinkRadioTransmit) fails on the bench and would break this dump
     * loop after chunk 0; the reference model emits every chunk to the
     * downlink, so use the non-blocking path (fire-and-forget radio). */
    if (!dispatchTelemetryPacket(&tm_packet, false)) {
      Serial.print("[ERROR] Transmiting: ");
      Serial.println(ret);
      ledBlink(8, LED_COLOR_RED);
      block_tx = false;
      return;
    }
    delay(100);
  }
  block_tx = false;
}

static void printSystemStatusDashboard(void) {
  const unsigned long uptime_ms = millis();
  const unsigned long uptime_s = uptime_ms / 1000UL;
  const unsigned int hh = (unsigned int)(uptime_s / 3600UL);
  const unsigned int mm = (unsigned int)((uptime_s % 3600UL) / 60UL);
  const unsigned int ss = (unsigned int)(uptime_s % 60UL);

  gps_nav_t nav = {0};
  gpsRead(&nav);

  float acc_x = 0, acc_y = 0, acc_z = 0, acc_temp = 0;
  float bme_temp = 0, bme_pressure = 0, bme_altitude = 0, bme_humidity = 0;
  accelerometerRead(&acc_x, &acc_y, &acc_z, &acc_temp);
  bmeRead(&bme_temp, &bme_pressure, &bme_altitude, &bme_humidity);

  const float latitude_deg = ((float)nav.latitudeE7) / 10000000.0f;
  const float longitude_deg = ((float)nav.longitudeE7) / 10000000.0f;
  const float altitude_m = ((float)nav.altitudeCm) / 100.0f;

  Serial.println("==================================================");
  Serial.println("--- SYSTEM STATUS DASHBOARD ---");
  Serial.printf("Satellite Uptime:    %02u:%02u:%02u (%lu ms)\r\n", hh, mm, ss,
                uptime_ms);
  Serial.println();
  Serial.println("--- RADIO SUBSYSTEM ---");
  Serial.printf("Downlink:            %u MHz\r\n", DOWNLINK_FREQ);
  Serial.printf("Uplink:              %u MHz\r\n", UPLINK_FREQ);
  Serial.println();
  Serial.println("--- GPS / NAV ---");
  Serial.printf("UART OK:             %s\r\n", nav.uartOk ? "true" : "false");
  Serial.printf("Connected:           %s\r\n", nav.connected ? "true" : "false");
  Serial.printf("NMEA Active:         %s\r\n", nav.nmeaActive ? "true" : "false");
  Serial.printf("GPS Fix Status:      %s\r\n", nav.hasFix ? "true" : "false");
  Serial.printf("Satellites Tracked:  %u\r\n", nav.satellites);
  Serial.printf("Latitude:            %.7f deg\r\n", latitude_deg);
  Serial.printf("Longitude:           %.7f deg\r\n", longitude_deg);
  Serial.printf("Altitude:            %.2f m\r\n", altitude_m);
  if (nav.hasDateTime) {
    Serial.printf("UTC Date/Time:       %04u-%02u-%02u %02u:%02u:%02u\r\n",
                  nav.utcYear, nav.utcMonth, nav.utcDay, nav.utcHour,
                  nav.utcMinute, nav.utcSecond);
  } else {
    Serial.println("UTC Date/Time:       (no fix)");
  }
  Serial.println();
  Serial.println("--- SENSOR TELEMETRY ---");
  Serial.println("Environmental Data:");
  Serial.printf("  Temperature:       %.2f C\r\n", bme_temp);
  Serial.printf("  Pressure:          %.2f hPa\r\n", bme_pressure);
  Serial.printf("  Humidity:          %.2f %%RH\r\n", bme_humidity);
  Serial.println();
  Serial.println("IMU State (raw):");
  Serial.printf("  Accel X/Y/Z:       %.3f / %.3f / %.3f\r\n", acc_x, acc_y,
                acc_z);
  Serial.println("==================================================");
}

void telemetryDashboardWorker(void) {
  if (millis() - t_dashboard_log.previous < t_dashboard_log.interval) {
    return;
  }
  t_dashboard_log.previous = millis();
  printSystemStatusDashboard();
}

void telemetryRadioWorker(void) {
  labTickWorkers();
  if (block_tx) {
    return;
  }
  /* V-19 bench parity: the simulator's periodic radio TM workers
   * (_workers_tick) are driven by the MODEL clock, which advances only
   * inside advance() -- they are frozen across the inter-window TC
   * phase. The board previously ran all five of these on real millis()
   * outside the windows: v130's 63 B covert FIFO was drained by a stray
   * 1 s beacon during the TC phase before the PoC's 2.2 s drain window,
   * and v106's measured cadence (14/20/22/30 s) wandered +/-0.6 s
   * (mean 21.3 s on a 22 s nominal). All five timers now ride the bench
   * epoch clock (labBenchMs), which runs 1:1 with wall time only while
   * a FEED window is open, so fires land on the exact bench grid --
   * deterministic booked gaps, like the simulator. */
  if (!labFeedActive()) {
    return;
  }
  const uint32_t bnow = labBenchMs();

  if (bnow - t_radio_tm_data.previous > t_radio_tm_data.interval) {
    t_radio_tm_data.previous = bnow;
    /* V-17/V-26 bench parity: the SB sensor-enable mask (MID 0x103) gates
     * the sensor TM exactly like the reference model -- mask 0 drops the
     * frame (sensors invisible to the operator), a missing ACC bit zeros
     * the accelerometer fields. */
    const uint8_t s_mask = sbSensorMask();
    if (s_mask & 0x01) {
      float tm, p, alt, hum;
      float x, y, z, t;
      bmeRead(&tm, &p, &alt, &hum);
      delay(100);
      accelerometerRead(&x, &y, &z, &t);
      if (!(s_mask & 0x02)) {
        x = y = z = t = 0.0f;
      }
      telemetrySPPPackFrame(x, y, z, t, tm, p, alt, hum);
    }
  }
  if (bnow - t_radio_nav.previous > t_radio_nav.interval) {
    t_radio_nav.previous = bnow;
    telemetrySPPTransmitNavSnapshot();
  }
  if (t_radio_beacon.interval != radio_beacon_interval_ms) {
    /* bench parity: the simulator can only fire the beacon once per
     * worker tick (100 ms), which caps an interval-0 "chatty beacon" at
     * 10 Hz; the silicon loop is ~500x faster and the uncapped storm
     * saturates core0 (every other TC waits minutes). Enforce the same
     * 100 ms floor on the effective gap. */
    const unsigned long beacon_gap =
        t_radio_beacon.interval < 100UL ? 100UL : t_radio_beacon.interval;
    if (bnow - t_radio_beacon.previous > beacon_gap) {
      t_radio_beacon.previous = bnow;
      telemetrySPPTransmitBeacon();
    }
  }
  if (bnow - t_radio_sync.previous > t_radio_sync.interval) {
    t_radio_sync.previous = bnow;
    telemetrySPPTransmitPingSync();
  }
  if (bnow - t_radio_idle.previous > t_radio_idle.interval) {
    t_radio_idle.previous = bnow;
    telemetrySPPTransmitIDLE();
  }
}

void labResetRadioWorkerPhase(void) {
  /* V-19 bench parity: re-anchor the five periodic radio workers when a
   * fresh bench epoch is consumed (cold-boot replay or harness REARM,
   * LAB_CTRL sub 6): the simulator resets its worker grid to 0 in
   * _cold_boot (t_prev = {0}), so the board's first radio TM lands one
   * full interval after the epoch, on the bench grid. */
  t_radio_tm_data.previous = 0;
  t_radio_nav.previous = 0;
  t_radio_sync.previous = 0;
  t_radio_idle.previous = 0;
  t_radio_beacon.previous = 0;
}

void commandApidHandler(space_packet_t *space_packet, command_source_t source) {
  uint16_t apid = space_packet->header.identification & 0x7FF;
  /* V-24 bench parity: feed the anomaly detector's TC-rate channel for
   * RADIO-sourced TCs only (mirrors flatsat_sim.py tc_seen, which the
   * simulator increments in the radio stats block). Without this the
   * board's channel was permanently 0 and the detector's TC-rate
   * residual could never exceed z*sigma on silicon. */
  if (source == COMMAND_SOURCE_RADIO) {
    labCountRadioTc();
  }
  tclAppend(apid, space_packet->header.sequence & 0x3FFF, space_packet->data,
            (uint8_t)(space_packet->header.length + 1));
  if (apid == SPP_APID_TC_PING) {
    // Pilot APID for the secondary-header format: same command, same
    // effect either way -- the SecHdr bit (already reconstructed in host
    // order by spp_unpack_packet) picks which reply format to use. The
    // legacy no-sec-header PING (still the default for every other tool
    // in this repo) is untouched.
    const uint8_t has_sec_header =
        (space_packet->header.identification >> 11) & 0x01;
    if (has_sec_header == SPP_SECHEAD_FLAG_PRESENT) {
      const uint32_t counter = ((uint32_t)space_packet->data[0] << 24) |
                               ((uint32_t)space_packet->data[1] << 16) |
                               ((uint32_t)space_packet->data[2] << 8) |
                               (uint32_t)space_packet->data[3];
      telemetrySPPTransmitPingAckSecured(counter);
    } else {
      telemetrySPPTransmitPingAck();
    }
  } else if (apid == SPP_APID_TC_RESETC) {
    ledBlink(4, LED_COLOR_RED);
    ledBlink(4, LED_COLOR_YELLOW);
    softwareReset();
  } else if (apid == SPP_APID_TC_SEND_FW) {
    telemetrySPPTransmitVersion();
  } else if (apid == SPP_APID_TC_SET_THRUSTER) {
    uint8_t thruster_id = space_packet->data[0];
    uint8_t thuster_power = space_packet->data[1];
    if (thruster_id == 0) {
      thrusterSetT0Power(thuster_power);
      /* V-33 bench parity: like flatsat_sim.py (0x04 handler), every
       * SET_THRUSTER TC delivers an unmitigated momentum impulse to the
       * model (0.3 deg/s at full power) -- the "10 Hz spam" pattern that
       * trips the 5 deg/s FDIR. Only the SB path had this effect on
       * silicon, so the TC path plateaued at ~4 deg/s. */
      if (thuster_power != 0) {
        missionModelThrusterEffect(0, thuster_power);
      }
      Serial.print("Thruster 0 changed to: ");
      Serial.println(thuster_power);
    } else if (thruster_id == 1) {
      Serial.print("Thruster 1 changed to: ");
      Serial.println(thuster_power);
      thrusterSetT1Power(thuster_power);
      if (thuster_power != 0) {
        missionModelThrusterEffect(1, thuster_power);
      }
    } else {
      Serial.println("[ERROR] Thruster not found");
    }
  } else if (apid == SPP_APID_TC_SET_BEACON_RATE) {
    uint8_t b_seconds = space_packet->data[0];
    if (b_seconds > 30) {
      Serial.println("[Error] The Beacon rate it is to high");
      return;
    }
    t_radio_beacon.interval = b_seconds * 1000;
    /* flatsat-lab v130 bench parity: the simulator books its first
     * post-SET_BEACON_RATE beacon one virtual tick AFTER the command
     * (tw["beacon"] only moves on fire; the v130 PoC's advance(1100)
     * windows are sized to catch exactly one beacon per window). With
     * `previous` left stale (boot 0 / the last 12 s prologue beacon)
     * the silicon fired an immediate catch-up stream that the harness'
     * tc() read window consumed -- on the v130 run six 1 s beacons
     * drained the 63 B covert FIFO before the PoC's windows, which then
     * saw only zero padding. Arm `previous` like the sim's virtual
     * clock (now the bench epoch clock, frozen outside FEED windows
     * exactly like the model clock): the first fire happens exactly one
     * interval after the command, in bench time. */
    t_radio_beacon.previous = labBenchMs();
  } else if (apid == SPP_APID_TC_BROADCAST_MSG) {
    uint16_t frequency = ((uint16_t)space_packet->data[0] << 8) |
                         (uint16_t)space_packet->data[1];
    size_t payload_total = space_packet->header.length + 1;
    size_t msg_len = payload_total - 2;
    uint8_t buffer_msg[SPP_MAX_PAYLOAD_CHUNK] = {0};

    memcpy(buffer_msg, space_packet->data + 2, msg_len);
    if (!mission_ctx.payloadArmed) {
      Serial.println("[WARN] Payload relay used outside payload mode");
    }
    /* V-32 counter-measure: with DEF_FREQ_LOCK the broadcast handler
     * refuses to re-point the downlink at a frequency outside the
     * operator whitelist BEFORE mutating any mission state. */
    if (labDefenseBit(0x04 /* DEF_FREQ_LOCK */) && frequency != 916) {
      Serial.println("[ERROR] FREQ LOCK");
      /* V-32 bench parity: the reference model answers a locked foreign
       * frequency with an error TM (_err("FREQ LOCK")); the console print
       * alone was invisible to the host. */
      telemetrySPPTransmitError("FREQ LOCK");
      return;
    }
    mission_ctx.lastPayloadFrequency = frequency;
    mission_ctx.payloadForwardCount++;
    mission_ctx.lastPayloadLength = (uint8_t)msg_len;
    /* V-31/V-32 bench parity: single shared forward counter (see covert.cpp
     * covertVccBumpUnconditional); 0x0C/0x0F expose covertVcc(). */
    covertVccBumpUnconditional();

    space_packet_t tm_packet;
    const int ret = telemetrySPPBuildPacket(
        &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
        SPP_APID_TM_BROADCAST_MSG, buffer_msg, msg_len);
    if (ret != SPP_ERROR_NONE) {
      Serial.print("[ERROR] Telemetry SPP Pack Frame: ");
      Serial.println(ret);
      ledBlink(8, LED_COLOR_RED);
      return;
    }
    const uint16_t total_len = packetTotalLen(&tm_packet);
    /* V-32/V-35 bench parity: the reference model echoes the broadcast TM
     * back on the downlink (self._frame(0x06, msg)); the host must see it. */
    obcUSBTransmitFrame((uint8_t *)&tm_packet, total_len);
    downlinkRadioTransmitBroadcast(frequency, (uint8_t *)&tm_packet,
                                   total_len);
    debugPrintTelemetryPacket(&tm_packet, "PAYLOAD_BROADCAST");
    logger_spp(&tm_packet);
  } else if (apid == SPP_APID_TC_FLASH) {
    ledBlink(4, LED_COLOR_YELLOW);
    telemetrySPPTransmitFlash();
  } else if (apid == SPP_APID_TC_AES_CONFIG) {
    commandAesConfigHandler(space_packet->data[0] != 0);
  } else if (apid == SPP_APID_TC_FLASH_READ) {
    uint8_t window_id = space_packet->data[0];
    uint16_t offset =
        (uint16_t)space_packet->data[1] | ((uint16_t)space_packet->data[2] << 8);
    uint8_t read_len = space_packet->data[3];
    uint16_t unlock =
        ((uint16_t)space_packet->data[4] << 8) | (uint16_t)space_packet->data[5];

    if (window_id != flash_window_id || unlock != flash_unlock_tag) {
      telemetrySPPTransmitError("FLASH WINDOW LOCKED");
      return;
    }
    telemetrySPPTransmitFlashRead(offset, read_len);
  } else if (apid == SPP_APID_TC_GET_STATUS) {
    telemetrySPPTransmitMissionStatus();
  } else if (apid == SPP_APID_TC_SET_MISSION_MODE) {
    const uint8_t new_mode = space_packet->data[0];
    if (new_mode > MISSION_MODE_CONTINGENCY) {
      telemetrySPPTransmitError("MISSION MODE INVALID");
      return;
    }
    missionApplyMode(new_mode);
    telemetrySPPTransmitMissionMode();
  } else if (apid == SPP_APID_TC_GET_NAV) {
    telemetrySPPTransmitNavSnapshot();
  } else if (apid == SPP_APID_TC_GET_PAYLOAD_STATUS) {
    telemetrySPPTransmitPayloadStatus();
  } else if (apid == SPP_APID_TC_DEBUG_CONFIG) {
    if (source != COMMAND_SOURCE_USB) {
      telemetrySPPTransmitError("DEBUG USB ONLY");
      return;
    }
    commandDebugConfigHandler(space_packet->data[0] != 0);
  } else if (apid == SPP_APID_TC_GS_MODE) {
    commandGroundStationModeHandler(space_packet, source);
  } else if (apid == SPP_APID_TC_GS_ACCESS) {
    commandGroundStationAccessHandler(space_packet);
  } else if (apid == SPP_APID_TC_GS_STATUS) {
    telemetrySPPTransmitGroundStatus();
  } else if (extCommandHandler(space_packet, apid, source)) {
    return;
  } else {
    Serial.printf("[ERROR] Unknown APID: 0x%02X \r\n", apid);
    telemetrySPPTransmitError("Error Unknown APID");
  }
}

static void commandHandlerInternal(uint8_t *buffer, uint16_t buffer_len,
                                   command_source_t source) {
  space_packet_t space_packet;
  int ret = spp_unpack_packet(&space_packet, buffer, buffer_len);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] Unpacking SPP: ");
    Serial.println(ret);
    /* V-24 bench fix (same pattern as the uplink RX handler, ruplink.cpp):
     * a malformed bench frame (rare host/USB desync) used to run the
     * BLOCKING ledBlink(8) = 3.2 s of delay() on core0's hot loop --
     * during a beacon-flood window (v014) that single stall ate ~30 of
     * the 100 ms beacon gates and the PoC's flood count fell below the
     * threshold. Same visual effect, now serviced by ledBlinkTick(). */
    ledBlinkRequest(8, LED_COLOR_YELLOW);
    return;
  }
  logger_spp_tc(&space_packet);
  const uint16_t apid = space_packet.header.identification & 0x7FF;

  if (source == COMMAND_SOURCE_RADIO) {
    int rssi = 0;
    float snr = 0.0f;
    float ferr = 0.0f;
    labRadioLastStats(&rssi, &snr, &ferr);
    labTcStatsNote(rssi, snr, ferr, apid);
  }

  /* SDLS security processing (V-07/V-08/V-09), before any payload
   * handling; USB is the trusted local bus, like a real OBC backdoor. */
  const sdls_result_t sdls_res =
      sdlsPreProcess(&space_packet, source == COMMAND_SOURCE_RADIO);
  if (sdls_res == SDLS_HANG) {
    Serial.println("[FATAL] SDLS SPI out of bounds -> bus fault");
    labFatalHang();
  } else if (sdls_res == SDLS_REJECT_MAC) {
    telemetrySPPTransmitError("SDLS MAC FAIL");
    ledBlink(4, LED_COLOR_YELLOW);
    return;
  } else if (sdls_res == SDLS_REJECT_ARC) {
    telemetrySPPTransmitError("SDLS ARC FAIL");
    ledBlink(4, LED_COLOR_YELLOW);
    return;
  } else if (sdls_res == SDLS_REJECT_HDR) {
    telemetrySPPTransmitError("SDLS SEC HDR REQ");
    return;
  }
  if (apid == SPP_APID_TC_AES_CONFIG || apid == SPP_APID_TC_DEBUG_CONFIG) {
    bool new_state = false;
    if (!extractToggleConfigMode(&space_packet, &new_state)) {
      Serial.println("[ERROR] Toggle config payload parse failed");
      telemetrySPPTransmitError(apid == SPP_APID_TC_AES_CONFIG
                                    ? "AES CONFIG FAIL"
                                    : "DEBUG CONFIG FAIL");
      ledBlink(8, LED_COLOR_YELLOW);
      return;
    }

    if (apid == SPP_APID_TC_DEBUG_CONFIG) {
      if (source != COMMAND_SOURCE_USB) {
        telemetrySPPTransmitError("DEBUG USB ONLY");
        ledBlink(4, LED_COLOR_YELLOW);
        return;
      }
      commandDebugConfigHandler(new_state);
      return;
    }

    const char *gs_reason = NULL;
    if (!groundStationCommandAllowed(&space_packet, source, &gs_reason)) {
      Serial.printf("[WARN] Ground station gate rejected APID 0x%03X: %s\r\n",
                    apid, gs_reason);
      telemetrySPPTransmitError(gs_reason);
      telemetrySPPTransmitGroundStatus();
      ledBlink(4, LED_COLOR_YELLOW);
      return;
    }
    commandAesConfigHandler(new_state);
    return;
  }

  // Secured-format PING pilot: bypasses secureLinkDecodeInPlace entirely,
  // same reasoning as telemetrySPPTransmitPingAckSecured() above -- no
  // crypto/security semantics implemented yet, so this stays independent
  // of secure_link's state instead of assuming a decrypt path that has no
  // concept of a secondary-header offset. The ground-station gate below
  // still applies, same as every other command.
  const uint8_t has_sec_header =
      (space_packet.header.identification >> 11) & 0x01;
  if (apid == SPP_APID_TC_PING && has_sec_header == SPP_SECHEAD_FLAG_PRESENT) {
    const char *gs_reason = NULL;
    if (!groundStationCommandAllowed(&space_packet, source, &gs_reason)) {
      Serial.printf("[WARN] Ground station gate rejected APID 0x%03X: %s\r\n",
                    apid, gs_reason);
      telemetrySPPTransmitError(gs_reason);
      telemetrySPPTransmitGroundStatus();
      ledBlink(4, LED_COLOR_YELLOW);
      return;
    }
    commandApidHandler(&space_packet, source);
    return;
  }

  if (!secureLinkDecodeInPlace(&space_packet, source)) {
    Serial.println("[ERROR] Secure link payload decrypt failed");
    telemetrySPPTransmitError("AES DECRYPT FAIL");
    ledBlink(8, LED_COLOR_YELLOW);
    return;
  }

  const char *gs_reason = NULL;
  if (!groundStationCommandAllowed(&space_packet, source, &gs_reason)) {
    Serial.printf("[WARN] Ground station gate rejected APID 0x%03X: %s\r\n", apid,
                  gs_reason);
    telemetrySPPTransmitError(gs_reason);
    telemetrySPPTransmitGroundStatus();
    ledBlink(4, LED_COLOR_YELLOW);
    return;
  }
  commandApidHandler(&space_packet, source);
}

void commandHandler(uint8_t *buffer, uint16_t buffer_len) {
  commandHandlerInternal(buffer, buffer_len, COMMAND_SOURCE_RADIO);
}

void commandHandlerRadio(uint8_t *buffer, uint16_t buffer_len) {
  commandHandlerInternal(buffer, buffer_len, COMMAND_SOURCE_RADIO);
}

/* USB RX ring (core1 producer -> core0 consumer) */
#define USB_RING_DEPTH 8
#define USB_RING_MAX 256
typedef struct {
  uint16_t len;
  uint8_t buf[USB_RING_MAX];
} usb_frame_slot_t;
static usb_frame_slot_t s_usb_ring[USB_RING_DEPTH];
static volatile uint8_t s_usb_head = 0;
static volatile uint8_t s_usb_tail = 0;

/* core1 liveness: loop1() increments s_core1_tick; core0's console worker
 * alarms (every 10 s) if the tick stops advancing. Silent while healthy. */
volatile uint32_t s_core1_tick = 0;

void core1StallAlarm(void) {
  static uint32_t seen = 0;
  static unsigned long last_alarm_ms = 0;
  static unsigned long last_change_ms = 0;
  if (s_core1_tick != seen) {
    seen = s_core1_tick;
    last_change_ms = millis();
    return;
  }
  if (millis() - last_alarm_ms > 10000UL) {
    last_alarm_ms = millis();
    /* gap = how long core1 has been frozen (bench diagnostic, V-24) */
    Serial.printf("[WARN] CORE1 STALLED tick=%lu ms=%lu gap=%lu\r\n",
                  (unsigned long)seen, (unsigned long)millis(),
                  (unsigned long)(millis() - last_change_ms));
  }
}

void commandHandlerUSB(uint8_t *buffer, uint16_t buffer_len) {
  /* Core1 (TinyUSB drain) must not run the command pipeline: Serial /
   * TinyUSB writes from two cores reset the device. Hand the frame to
   * core0 via a small lock-free ring instead. */
  if (buffer_len == 0 || buffer_len > USB_RING_MAX) {
    return; /* oversized: dropped, host times out and retries */
  }
  const uint8_t next = (uint8_t)((s_usb_head + 1) % USB_RING_DEPTH);
  if (next == s_usb_tail) {
    return; /* ring full: dropped, host times out and retries */
  }
  memcpy(s_usb_ring[s_usb_head].buf, buffer, buffer_len);
  s_usb_ring[s_usb_head].len = buffer_len;
  s_usb_head = next;
}

void commandUsbDrainRing(void) {
  while (s_usb_tail != s_usb_head) {
    usb_frame_slot_t *slot = &s_usb_ring[s_usb_tail];
    commandHandlerInternal(slot->buf, slot->len, COMMAND_SOURCE_USB);
    s_usb_tail = (uint8_t)((s_usb_tail + 1) % USB_RING_DEPTH);
  }
}

/* =====================================================================
 * flatsat-lab v2 -- lab hooks (see labhooks.h)
 *
 * Thin accessors over the static mission context above, plus the reboot /
 * hang / RCE plumbing shared by the extension modules. On the RP2040
 * target the watchdog scratch registers are the real hardware registers
 * (they survive watchdog_reboot, which is the whole point of V-21); in
 * host builds plain globals stand in so the logic stays testable.
 * ===================================================================== */

#include "anomaly.h"
#include "covert.h"
#include "fdir.h"

#define LAB_PERSIST_COOKIE 0x53524550UL /* 'PERS' little-endian */
#define LAB_WDT_BOOTCOUNT_SLOT 5
#define LAB_WDT_COOKIE_SLOT 7

#if defined(ARDUINO_ARCH_RP2040)
static volatile uint32_t *const s_wdt_scratch = &watchdog_hw->scratch[0];
#else
static uint32_t s_host_scratch[8] = {0};
static bool s_host_hang_flag = false;
static bool s_host_reboot_flag = false;
bool labHostHangFlag(void) { return s_host_hang_flag; }
bool labHostRebootFlag(void) { return s_host_reboot_flag; }
static volatile uint32_t *const s_wdt_scratch = s_host_scratch;
#endif

static uint32_t s_lab_boot_count = 0;

uint32_t labWatchdogScratch(uint8_t index) {
  return (index < 8) ? s_wdt_scratch[index] : 0;
}

void labWatchdogScratchSet(uint8_t index, uint32_t value) {
  if (index < 8) {
    s_wdt_scratch[index] = value;
  }
}

bool labPersistentCookiePresent(void) {
  return labWatchdogScratch(LAB_WDT_COOKIE_SLOT) == LAB_PERSIST_COOKIE;
}

uint32_t labBootCount(void) { return s_lab_boot_count; }

void labReboot(void) {
  /* ack first so the PoC sees the boot counter bump (V0-08 + V-21) */
  uint8_t ack[4] = {SPACECRAFT_ID, (uint8_t)(s_lab_boot_count + 1),
                    labPersistentCookiePresent() ? 1 : 0, 0x52};
  labTmSend(SPP_APID_TM_RESETC, ack, 4, true);
  delay(500); /* let the CDC IN transfers drain before the reset (hw) */
  labWatchdogScratchSet(LAB_WDT_BOOTCOUNT_SLOT, s_lab_boot_count + 1);
#if defined(ARDUINO_ARCH_RP2040)
  watchdog_enable(50, 1);
  while (1) {
  }
#else
  s_host_reboot_flag = true;
#endif
}

void labRebootBrownout(void) {
  /* a brownout is a *power* event: unlike labReboot it wipes the scratch
   * registers too -- clearing the persistence cookie (power-cycle-only
   * cleanup, the V-21 lesson) and restarting the boot count. */
  uint8_t ack[4] = {SPACECRAFT_ID, 0, 0, 0x42 /* 'B' brownout */};
  labTmSend(SPP_APID_TM_RESETC, ack, 4, true);
  delay(500); /* let the ack flush to the host before the power-event (hw) */
  for (uint8_t i = 0; i < 8; i++) {
    labWatchdogScratchSet(i, 0);
  }
#if defined(ARDUINO_ARCH_RP2040)
  /* 1 ms never fires on this silicon (watchdog tick granularity); 50 ms is
   * the proven reboot window (same as labReboot). */
  watchdog_enable(50, 1);
  while (1) {
  }
#else
  s_host_reboot_flag = true;
#endif
}

void labFatalHang(void) {
  /* no watchdog was ever armed (V0-15): this while(1) is mission loss */
#if defined(ARDUINO_ARCH_RP2040)
  while (1) {
  }
#else
  s_host_hang_flag = true;
#endif
}

/* ---- mission state accessors ---------------------------------------- */
uint8_t labMissionMode(void) { return mission_ctx.mode; }
void labApplyMissionMode(uint8_t mode) { missionApplyMode(mode); }
uint8_t labStatusFlags(void) { return missionStatusFlags(); }
bool labSecureLinkEnabled(void) { return secureLinkIsEnabled(); }

/* V-05 bench parity: expose the live GS challenge so memserv can serve it
 * at the simulator's SYM_GS_CHALLENGE address. */
uint32_t labGsChallengeGet(void) {
  return mission_ctx.groundStationChallenge;
}
void labSecureLinkSetEnabled(bool enabled) { secureLinkSetEnabled(enabled); }
bool labUsbDebugEnabled(void) { return mission_ctx.usbDebugEnabled; }
void labUsbDebugEnabledSet(bool enabled) {
  mission_ctx.usbDebugEnabled = enabled;
}
void labPayloadArmedSet(bool armed) { mission_ctx.payloadArmed = armed; }
bool labGsModeEnabled(void) { return mission_ctx.groundStationModeEnabled; }
void labGsModeSet(bool enabled) {
  mission_ctx.groundStationModeEnabled = enabled;
  if (!enabled) {
    groundStationClearSession();
    groundStationClearHandshake();
  }
}
uint32_t labGsChallengeValue(void) { return mission_ctx.groundStationChallenge; }
uint32_t labGsExpectedResponseFor(uint32_t challenge) {
  return groundStationExpectedResponse(challenge);
}

/* V-28 bench parity: see labhooks.h. The bench ground station (and the
 * PoC standing in for the attacker) predicts the challenge from its own
 * synced mission clock -- the now_ms of the last LAB_STATUS it read.
 * Seeding from the craft's live millis() at generation time instead added
 * the bench's USB + pipeline latency (~0.3-2 s) to the seed, so the
 * ground station's prediction could never match on silicon. */
static volatile uint32_t s_last_lab_sync_ms = 0;
void labMarkLabStatusSync(uint32_t ms) { s_last_lab_sync_ms = ms; }
uint32_t labLastLabSyncMs(void) { return s_last_lab_sync_ms; }
bool labGsSessionActive(void) { return groundStationSessionActive(); }
uint16_t labTmCounter(void) { return sppTmCounterPeek(); }

void labSetBeaconIntervalMs(uint32_t interval_ms) {
  t_radio_beacon.interval = interval_ms;
}

uint8_t labExtFlags(void) {
  uint8_t f = 0;
  if (anomalyAlarmActive()) {
    f |= LAB_FLAG2_ANOMALY;
  }
  if (fdirSafeActive()) {
    f |= LAB_FLAG2_SAFE;
  }
  fs_ota_status_t ota_st;
  otaGetStatus(&ota_st);
  if (ota_st.booted_slot == 1) {
    f |= LAB_FLAG2_OTA_B;
  }
  if (sdlsIsEnabled()) {
    f |= LAB_FLAG2_SDLS;
  }
  mission_model_t mm;
  missionModelGet(&mm);
  if (mm.brownout_armed) {
    f |= LAB_FLAG2_BROWNOUT;
  }
  if (labPersistentCookiePresent()) {
    f |= LAB_FLAG2_PERSIST;
  }
  return f;
}

/* ---- telemetry plumbing ---------------------------------------------- */
void labTmSend(uint16_t apid, const uint8_t *data, uint16_t data_len,
               bool force_cleartext) {
  /* The DEF_TM_CTR (V-11) keystream decision is applied inside
   * telemetrySPPBuildPacketEx() so that base-family and lab-extension
   * TMs behave identically to the reference model. */
  space_packet_t tm_packet;
  const int ret = telemetrySPPBuildPacketEx(
      &tm_packet, SPP_GROUP_FLAG_UNSEGMENTED, SPP_SECHEAD_FLAG_NOPRESENT, 0,
      apid, data, data_len, force_cleartext);
  if (ret != SPP_ERROR_NONE) {
    Serial.print("[ERROR] labTmSend pack: ");
    Serial.println(ret);
    return;
  }
  dispatchTelemetryPacket(&tm_packet, false);
}

void labTmError(const char *message) { telemetrySPPTransmitError(message); }

/* ---- injected TCs (schedule replay, contingency dictionary) ---------- */
void labInjectTc(uint16_t apid, const uint8_t *payload, uint16_t len,
                 uint8_t source) {
  space_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.header.identification = (uint16_t)(apid & 0x7FF);
  pkt.header.sequence = 0;
  pkt.header.length = (uint16_t)(len == 0 ? 0 : len - 1);
  if (payload != NULL && len > 0) {
    memcpy(pkt.data, payload, (len > SPP_MAX_PAYLOAD_CHUNK) ? SPP_MAX_PAYLOAD_CHUNK : len);
  }
  commandApidHandler(&pkt,
                     (source == LAB_SRC_USB) ? COMMAND_SOURCE_USB
                                             : COMMAND_SOURCE_RADIO);
}

/* ---- radio stats ------------------------------------------------------ */
static bool s_stats_override = false;
static int s_stats_rssi = -95;
static float s_stats_snr = 8.0f;
static float s_stats_ferr = 0.0f;

void labRadioStatsOverride(int rssi, float snr, float freq_error, bool armed) {
  s_stats_override = armed;
  if (armed) {
    s_stats_rssi = rssi;
    s_stats_snr = snr;
    s_stats_ferr = freq_error;
  }
}

void labRadioLastStats(int *rssi, float *snr, float *freq_error) {
  if (s_stats_override) { /* LAB_CTRL bench bridge wins over the PHY */
    if (rssi) {
      *rssi = s_stats_rssi;
    }
    if (snr) {
      *snr = s_stats_snr;
    }
    if (freq_error) {
      *freq_error = s_stats_ferr;
    }
    return;
  }
#if defined(ARDUINO_ARCH_RP2040)
  radioLastStats(rssi, snr, freq_error);
#else
  if (rssi) {
    *rssi = -95;
  }
  if (snr) {
    *snr = 8.0f;
  }
  if (freq_error) {
    *freq_error = 0.0f;
  }
#endif
}

bool labPayloadArmed(void) { return mission_ctx.payloadArmed; }

void labInjectFrameAsRadio(uint8_t *frame, uint16_t len) {
  commandHandler(frame, len);
}

/* ---- RCE symbol table (V-14) -----------------------------------------
 * These functions exist in the image; MEMCPY + VTOR retarget makes the
 * next interrupt vector into them, exactly like the Flying Laptop
 * "TC memcpy" case. The Python simulator carries the same six names. */
extern "C" {
void labFnDetumble(void) __attribute__((noinline));
void labFnDetumble(void) { missionModelDetumble(true); }
void labFnLedRainbow(void) __attribute__((noinline));
void labFnLedRainbow(void) {
  ledBlink(3, LED_COLOR_RED);
  ledBlink(3, LED_COLOR_GREEN);
  ledBlink(3, LED_COLOR_BLUE);
}
void labFnGsModeOff(void) __attribute__((noinline));
void labFnGsModeOff(void) { labGsModeSet(false); }
void labFnBeaconFlood(void) __attribute__((noinline));
void labFnBeaconFlood(void) { labSetBeaconIntervalMs(0); }
void labFnSecureLinkOff(void) __attribute__((noinline));
void labFnSecureLinkOff(void) { secureLinkSetEnabled(false); }
void labFnNoop(void) __attribute__((noinline, used));
void labFnNoop(void) {}
}

/* The recognised target values are the ground station's FIXED synthetic
 * addresses (flatsat_sim.py SYMBOLS): the PoCs -- standing in for an
 * attacker who analysed the public firmware -- write exactly those values
 * to VTOR, on the bench and in the simulator alike. Matching on the real
 * (build-dependent) function addresses broke bench parity: the board wrote
 * the real SCB->VTOR register but the takeover check never fired, so the
 * RCE confirmation marker was missing on silicon. */
static const lab_symbol_t s_symbols[LAB_SYMBOL_COUNT] = {
    {"labFnDetumble", 0x10012340UL, labFnDetumble},
    {"labFnLedRainbow", 0x10012440UL, labFnLedRainbow},
    {"labFnGsModeOff", 0x10012540UL, labFnGsModeOff},
    {"labFnBeaconFlood", 0x10012640UL, labFnBeaconFlood},
    {"labFnSecureLinkOff", 0x10012740UL, labFnSecureLinkOff},
    {"labFnNoop", 0x10012000UL, labFnNoop},
};

const lab_symbol_t *labSymbolTable(void) { return s_symbols; }

const char *labVtorRedirectCheck(uint32_t new_vtor) {
  for (uint8_t i = 0; i < LAB_SYMBOL_COUNT; i++) {
    if (s_symbols[i].addr == new_vtor) {
      /* On silicon the effect happens by hardware (next IRQ). Fire it in
       * software too so the telemetry reflects the takeover immediately,
       * and announce it -- a ground operator sees a ghost command. */
      uint8_t tm[8] = {SPACECRAFT_ID, 1, 0, 0, 'R', 'C', 'E', '\0'};
      s_symbols[i].fn();
      labTmSend(SPP_APID_TC_MEMCPY, tm, 8, true);
      return s_symbols[i].name;
    }
  }
  return NULL;
}

/* ---- boot ------------------------------------------------------------ */
void labBootInit(void) {
  s_lab_boot_count = labWatchdogScratch(LAB_WDT_BOOTCOUNT_SLOT);
#if defined(ARDUINO_ARCH_RP2040)
  /* Watchdog scratch survives resets but NOT power rails: a cold battery
   * power-on leaves RP2040 scratch uninitialised. Values beyond a sane
   * boot count (the lab never reaches 1M reboots) are treated as garbage
   * and re-seeded to 0. The V-21 cookie slot keeps its full 32-bit
   * magic-value discipline, so no sanitising is needed there. */
  if (s_lab_boot_count > 0x100000UL && !watchdog_caused_reboot()) {
    s_lab_boot_count = 0;
    labWatchdogScratchSet(LAB_WDT_BOOTCOUNT_SLOT, 0);
  } else if (s_lab_boot_count > 0x100000UL) {
    /* reboot with garbage: the chain never had a sane root, restart it */
    s_lab_boot_count = 0;
    labWatchdogScratchSet(LAB_WDT_BOOTCOUNT_SLOT, 1);
  }
#endif
#if defined(ARDUINO_ARCH_RP2040)
  /* Watchdog scratch survives resets but NOT power rails: a cold battery
   * power-on leaves RP2040 scratch uninitialised. Values beyond a sane
   * boot count (the lab never reaches 1M reboots) are treated as garbage
   * and re-seeded to 0. The V-21 cookie slot keeps its full 32-bit
   * magic-value discipline, so no sanitising is needed there. */
  if (s_lab_boot_count > 0x100000UL && !watchdog_caused_reboot()) {
    s_lab_boot_count = 0;
    labWatchdogScratchSet(LAB_WDT_BOOTCOUNT_SLOT, 0);
  } else if (s_lab_boot_count > 0x100000UL) {
    /* reboot with garbage: the chain never had a sane root, restart it */
    s_lab_boot_count = 0;
    labWatchdogScratchSet(LAB_WDT_BOOTCOUNT_SLOT, 1);
  }
#endif

  missionModelBoot();
  sdlsBootDefaults();
  fdirBootDefaults();
  fsBoot();

  /* V-21: a persistence cookie left in watchdog scratch by an exploit
   * re-applies its effects at every boot, and only a power cycle (or a
   * brownout) can clear it -- in orbit that means a battery event. */
  if (labPersistentCookiePresent()) {
    secureLinkSetEnabled(false);
    mission_ctx.groundStationModeEnabled = false;
  }

  /* V-19: persisted scheduled telecommands replay without re-auth */
  schedReplayAtBoot();
}
