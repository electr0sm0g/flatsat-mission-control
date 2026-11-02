/*  - extcmds.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Payload wire formats are normative for the Python simulator and every
 * PoC -- see docs/writeups/*.md per vulnerability.
 */
#include "extcmds.h"
#include "anomaly.h"
#include "covert.h"
#include "fdir.h"
#include "flashstore.h"
#include "memserv.h"
#include "mission_model.h"
#include "sb.h"
#include "sdls_sim.h"
#include "sensors.h"
#include "spacecan.h"
#include "thruster.h"
#include <math.h>
#include <string.h>

static uint8_t s_defense_flags = DEF_ANOMALY_EN; /* anomaly on by default */

uint8_t labDefenseFlags(void) { return s_defense_flags; }
void labDefenseSet(uint8_t flags) {
  s_defense_flags = flags;
  tclSetEnabled((flags & DEF_LOG_ENABLE) != 0);
  anomalySetEnabled((flags & DEF_ANOMALY_EN) != 0);
}
bool labDefenseBit(uint8_t bit) { return (s_defense_flags & bit) != 0; }
bool labBeaconCloaked(void) { return labDefenseBit(DEF_CLOAK); }

static uint16_t be16v_(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t be32v_(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static uint32_t le32v_(const uint8_t *p) {
  return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[1] << 8) | p[0];
}
static uint16_t le16v_(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static void put16le_(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)(v >> 8);
}

/* --------------------------------------------------------- TC stats ---- */
#define TCSTATS_WINDOW 64
static int32_t s_tc_rssi_sum = 0;
static int32_t s_tc_snr_sum = 0; /* x10 */
static int32_t s_tc_ferr_sum = 0; /* Hz */
static int32_t s_tc_rssi_min = 0;
static int32_t s_tc_rssi_max = 0;
static uint8_t s_tc_count = 0;
static uint16_t s_tc_last_apid = 0;

void labTcStatsNote(int rssi, float snr, float freq_error, uint16_t apid) {
  if (s_tc_count == 0) {
    s_tc_rssi_min = rssi;
    s_tc_rssi_max = rssi;
  }
  s_tc_rssi_sum += rssi;
  s_tc_snr_sum += (int32_t)(snr * 10.0f);
  s_tc_ferr_sum += (int32_t)freq_error;
  if (rssi < s_tc_rssi_min) {
    s_tc_rssi_min = rssi;
  }
  if (rssi > s_tc_rssi_max) {
    s_tc_rssi_max = rssi;
  }
  if (s_tc_count < TCSTATS_WINDOW) {
    s_tc_count++;
  } else { /* rolling window: subtract oldest approximation */
    s_tc_rssi_sum -= (s_tc_rssi_sum / s_tc_count);
    s_tc_snr_sum -= (s_tc_snr_sum / s_tc_count);
    s_tc_ferr_sum -= (s_tc_ferr_sum / s_tc_count);
  }
  s_tc_last_apid = apid;
}

/* ------------------------------------------------------ payload parse -- */
#define PL ((uint16_t)(space_packet->header.length + 1))
#define D (space_packet->data)

static uint8_t srcToSb_(command_source_t source) {
  return (source == COMMAND_SOURCE_USB) ? 1 : 0;
}

/* handlers return true when handled */
static bool hGpsOverride(space_packet_t *space_packet, command_source_t source);
static bool hSdls(space_packet_t *space_packet, command_source_t source);
static bool hKeyVerify(space_packet_t *space_packet);
static bool hMemory(space_packet_t *space_packet, uint16_t apid);
static bool hLogName(space_packet_t *space_packet);
static bool hSb(space_packet_t *space_packet, command_source_t source);
static bool hScInject(space_packet_t *space_packet, command_source_t source);
static bool hFdir(space_packet_t *space_packet);
static bool hSched(space_packet_t *space_packet);
static bool hOta(space_packet_t *space_packet);
static bool hTcStats(space_packet_t *space_packet);
static bool hPadding(space_packet_t *space_packet);
static bool hCovert(space_packet_t *space_packet);
static bool hSnap(space_packet_t *space_packet);
static bool hHeater(space_packet_t *space_packet);
static bool hDefenses(space_packet_t *space_packet);
static bool hLabStatus(space_packet_t *space_packet);
static bool hLabCtrl(space_packet_t *space_packet, command_source_t source);

bool extCommandHandler(space_packet_t *space_packet, uint16_t apid,
                       command_source_t source) {
  /* EX-0006.01: maintenance/test APIDs only accepted while safe-mode
   * relaxations are active. */
  if (apid >= SPP_APID_TEST_FIRST && apid <= SPP_APID_TEST_LAST) {
    if (!fdirTestmode()) {
      labTmError("TESTMODE INACTIVE");
      return true;
    }
    uint8_t tm[5] = {(uint8_t)apid, 'T', 'E', 'S', 'T'};
    labTmSend(apid, tm, 5, false);
    return true;
  }

  switch (apid) {
  case SPP_APID_TC_GPS_OVERRIDE:
    return hGpsOverride(space_packet, source);
  case SPP_APID_TC_SDLS_CONFIG:
  case SPP_APID_TC_SDLS_OTA:
    return hSdls(space_packet, source);
  case SPP_APID_TC_KEY_VERIFY:
    return hKeyVerify(space_packet);
  case SPP_APID_TC_MEMCPY:
  case SPP_APID_TC_MEM_READ:
    return hMemory(space_packet, apid);
  case SPP_APID_TC_SET_LOG_NAME:
    return hLogName(space_packet);
  case SPP_APID_TC_SB_PUBLISH:
    return hSb(space_packet, source);
  case SPP_APID_TC_SC_INJECT:
    return hScInject(space_packet, source);
  case SPP_APID_TC_FDIR_CONFIG:
    return hFdir(space_packet);
  case SPP_APID_TC_SCHED:
    return hSched(space_packet);
  case SPP_APID_TC_OTA:
    return hOta(space_packet);
  case SPP_APID_TC_TC_STATS:
    return hTcStats(space_packet);
  case SPP_APID_TC_PADDING_CONFIG:
    return hPadding(space_packet);
  case SPP_APID_TC_COVERT_ENQ:
    return hCovert(space_packet);
  case SPP_APID_TC_PAYLOAD_SNAP:
    return hSnap(space_packet);
  case SPP_APID_TC_HEATER:
    return hHeater(space_packet);
  case SPP_APID_TC_DEFENSES_CONFIG:
    return hDefenses(space_packet);
  case SPP_APID_TC_LAB_STATUS:
    return hLabStatus(space_packet);
  case SPP_APID_TC_LAB_CTRL:
    return hLabCtrl(space_packet, source);
  default:
    return false;
  }
}

/* ------------------------------------------------------------ handlers */
/* NB: extern from sensors.cpp (GPS override injection + plausibility). */
extern void gpsInjectOverride(int32_t lat_e7, int32_t lon_e7, int32_t alt_cm,
                              uint8_t sats, bool valid);

static bool hGpsOverride(space_packet_t *space_packet,
                         command_source_t source) {
  (void)source;
  if (PL < 13) {
    labTmError("GPS OVR FORMAT");
    return true;
  }
  const int32_t lat = (int32_t)le32v_(D);
  const int32_t lon = (int32_t)le32v_(D + 4);
  const int32_t alt = (int32_t)le32v_(D + 8);
  const uint8_t sats = D[12];
  gpsInjectOverride(lat, lon, alt, sats, true);

  uint8_t tm[18] = {SPACECRAFT_ID};
  memcpy(tm + 1, D, 13);
  tm[14] = covertPaddingMode();
  tm[15] = labDefenseFlags();
  tm[16] = labMissionMode();
  tm[17] = '\0';
  labTmSend(SPP_APID_TM_NAV, tm, 18, false);
  return true;
}

static bool hSdls(space_packet_t *space_packet, command_source_t source) {
  if (PL < 1) {
    labTmError("SDLS FORMAT");
    return true;
  }

  uint8_t tm[24] = {SPACECRAFT_ID};
  const uint16_t apid = space_packet->header.identification & 0x7FF;
  if (apid == SPP_APID_TC_SDLS_CONFIG) {
    /* CONFIG: [mode][arc_bits][window] */
    if (PL < 3) {
      labTmError("SDLS CFG FORMAT");
      return true;
    }
    sdlsConfigure(D[0], D[1], D[2]);
    tm[1] = 0x15;
    tm[2] = sdlsIsEnabled() ? 1 : 0;
    tm[3] = sdlsArcBits();
    tm[4] = sdlsWindow();
    tm[5] = (uint8_t)sdlsIsEnabled();
    labTmSend(SPP_APID_TC_SDLS_CONFIG, tm, 6, true);
    return true;
  }

  /* OTA/OTAR family (APID 0x16): [sub][...] */
  if (PL < 1) {
    labTmError("SDLS OTA FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 0) { /* OTAR */
    if (PL < 19) {
      labTmError("OTAR FORMAT");
      return true;
    }
    uint8_t installed[16];
    const bool ok = sdlsOtar(D[1], D[2], D + 3, installed);
    tm[1] = 0x00;
    tm[2] = (uint8_t)(ok ? 1 : 0);
    tm[3] = D[1];
    tm[4] = D[2];
    labTmSend(SPP_APID_TC_SDLS_OTA, tm, 5, true);
    return true;
  }
  if (sub == 1) { /* SA_SET [1][sa][est][ast][key16] */
    if (PL < 20) {
      labTmError("SA SET FORMAT");
      return true;
    }
    const bool ok = sdlsSaSet(D[1], D[2], D[3], D + 4);
    tm[1] = 0x01;
    tm[2] = (uint8_t)(ok ? 1 : 0);
    tm[3] = D[1];
    labTmSend(SPP_APID_TC_SDLS_OTA, tm, 4, true);
    return true;
  }
  if (sub == 2) { /* SA_DUMP */
    if (PL < 2) {
      labTmError("SA DUMP FORMAT");
      return true;
    }
    const sdls_sa_t *sa = sdlsGetSa(D[1]);
    uint8_t dump[24] = {SPACECRAFT_ID, 0x02, D[1], sa->est, sa->ast};
    if (source == COMMAND_SOURCE_USB || labGsSessionActive()) {
      memcpy(dump + 5, sa->key, 16);
    } else {
      memset(dump + 5, 0, 16); /* radio without auth: keys stay quiet */
    }
    uint8_t nulls = 0;
    sdlsMasterKeyNullCount(&nulls);
    dump[21] = nulls;
    dump[22] = sdlsIsEnabled() ? 1 : 0;
    dump[23] = '\0';
    labTmSend(SPP_APID_TC_SDLS_OTA, dump, 24, true);
    return true;
  }
  if (sub == 3) { /* ARC reset -- deliberately unauthenticated: this is
                   * exactly why ARC-after-reset is a weak freshness gate */
    sdlsArcReset();
    tm[1] = 0x03;
    tm[2] = 1;
    labTmSend(SPP_APID_TC_SDLS_OTA, tm, 3, true);
    return true;
  }
  labTmError("SDLS OTA SUB?");
  return true;
}

static bool hKeyVerify(space_packet_t *space_packet) {
  if (PL < 21) {
    labTmError("KV FORMAT");
    return true;
  }
  uint8_t out[16];
  sdlsKeyVerify(D[0], D + 1, D + 5, out);
  uint8_t tm[19] = {SPACECRAFT_ID, D[0]};
  memcpy(tm + 2, out, 16);
  tm[18] = '\0';
  /* V-11: CTR oracle reply, no freshness state updated on purpose */
  labTmSend(SPP_APID_TC_KEY_VERIFY, tm, 19, true);
  return true;
}

static bool hMemory(space_packet_t *space_packet, uint16_t apid) {
  if (apid == SPP_APID_TC_MEM_READ) {
    if (PL < 6) {
      labTmError("MEM READ FORMAT");
      return true;
    }
    const uint32_t addr = le32v_(D);
    const uint16_t len = le16v_(D + 4);
    uint8_t buf[200];
    if (!memservRead(addr, len, buf)) {
      labTmError("MEM READ FAULT");
      return true;
    }
    uint8_t tm[8 + 200];
    tm[0] = SPACECRAFT_ID;
    memcpy(tm + 1, D, 6);
    memcpy(tm + 7, buf, len);
    labTmSend(SPP_APID_TC_MEM_READ, tm, (uint16_t)(7 + len), true);
    return true;
  }

  /* MEMCPY: [src u32 LE][dst u32 LE][len u16 LE] */
  if (PL < 10) {
    labTmError("MEMCPY FORMAT");
    return true;
  }
  const uint32_t src = le32v_(D);
  const uint32_t dst = le32v_(D + 4);
  const uint16_t len = le16v_(D + 8);
  if (!memservCopy(src, dst, len)) {
    labFatalHang(); /* unmapped destination == bus fault, no watchdog */
  }
  uint8_t tm[12] = {SPACECRAFT_ID, 1};
  memcpy(tm + 2, D, 10);
  labTmSend(SPP_APID_TC_MEMCPY, tm, 12, true);
  return true;
}

static bool hLogName(space_packet_t *space_packet) {
  char name[256] = {0};
  const uint16_t n = (PL > sizeof(name) - 1) ? sizeof(name) - 1 : PL;
  memcpy(name, D, n);
  name[n] = '\0';
  memservSetLogName(name);
  uint8_t tm[8] = {SPACECRAFT_ID, (uint8_t)labUsbDebugEnabled(),
                   (uint8_t)labSecureLinkEnabled(), (uint8_t)labGsModeEnabled(),
                   covertPaddingMode(), 0, 0, '\0'};
  labTmSend(SPP_APID_TC_SET_LOG_NAME, tm, 8, true);
  return true;
}

static bool hSb(space_packet_t *space_packet, command_source_t source) {
  if (PL < 3) {
    labTmError("SB FORMAT");
    return true;
  }
  const uint16_t mid = be16v_(D);
  const bool ok = sbPublish(mid, D + 2, (uint16_t)(PL - 2), srcToSb_(source));
  uint8_t tm[8] = {SPACECRAFT_ID, 1, (uint8_t)(mid >> 8), (uint8_t)mid,
                   (uint8_t)(ok ? 1 : 0), sbSensorMask(), (uint8_t)(covertVccFrozen() ? 1 : 0), '\0'};
  labTmSend(SPP_APID_TC_SB_PUBLISH, tm, 8, true);
  return true;
}

static bool hScInject(space_packet_t *space_packet, command_source_t source) {
  (void)source;
  if (PL < 1) {
    labTmError("SC FORMAT");
    return true;
  }
  /* [mode][can_id BE32][dlc][data...]  mode: 0 frame, 1 flood, 2 status,
   * 3 reset-node, 4 reassembly-overflow */
  const uint8_t mode = D[0];
  uint32_t can_id = 0;
  uint8_t dlc = 0;
  const uint8_t *data = D + 6;
  if (mode == 0 || mode == 3) {
    if (PL < 6) {
      labTmError("SC INJ FORMAT");
      return true;
    }
    can_id = be32v_(D + 1);
    dlc = D[5];
    if (dlc > 8 || PL < (uint16_t)(6 + dlc)) {
      labTmError("SC DLC");
      return true;
    }
  }
  uint8_t node_id = (uint8_t)(can_id & SC_CAN_NODE_MASK);
  if (mode == 3) {
    spacecanResetNode(node_id);
  }

  uint8_t status = 0;
  uint8_t busoff_mask = 0;
  uint8_t congested = 0;
  if (mode == 0) {
    status = spacecanRadioInject(can_id, dlc, data) ? 1 : 0;
  } else if (mode == 1) {
    const uint8_t n = (PL > 1) ? D[1] : 32;
    status = (uint8_t)(spacecanRadioFlood(n ? n : 32) ? 1 : 0);
  } else if (mode == 4) {
    status = spacecanRadioReassemblyOverflow() ? 1 : 0;
  }
  busoff_mask = spacecanBusoffMask();
  congested = spacecanCongested() ? 1 : 0;

  uint8_t tm[8] = {SPACECRAFT_ID, mode, status, busoff_mask, congested,
                   (uint8_t)(spacecanLastErrCount() & 0xFF),
                   (uint8_t)(spacecanLastErrCount() >> 8), '\0'};
  labTmSend(SPP_APID_TC_SC_INJECT, tm, 8, true);
  return true;
}

static bool hFdir(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("FDIR FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  mission_model_t mm;
  missionModelGet(&mm);

  if (sub == 0) { /* status */
    /* V-24 bench parity: the reference model's 18-byte layout
     * (flatsat_sim.py _fdir_cfg sub 0): [8:10]=tilt [10:12]=bus_v
     * [12:14]=power (LE16 x100), [14]=eclipse [15]=anomaly alarm,
     * [16]=last alarm channel, [17]=orbit clock (0..94). The previous
     * 20-byte variant inserted battery_pct at [12:14] and shifted the
     * alarm/channel fields one byte, so consumers reading the model
     * offsets saw power_hi/eclipse instead. */
    uint8_t tm[18] = {SPACECRAFT_ID, 0, (uint8_t)fdirSafeActive(),
                      (uint8_t)fdirArmed()};
    tm[4] = (uint8_t)(fdirTriggerCount() >> 24);
    tm[5] = (uint8_t)(fdirTriggerCount() >> 16);
    tm[6] = (uint8_t)(fdirTriggerCount() >> 8);
    tm[7] = (uint8_t)fdirTriggerCount();
    put16le_(tm + 8, (uint16_t)(mm.tilt_dps * 100.0f));
    put16le_(tm + 10, (uint16_t)(mm.bus_voltage * 100.0f));
    put16le_(tm + 12, (uint16_t)(mm.power_w * 100.0f));
    tm[14] = mm.eclipse ? 1 : 0;
    tm[15] = anomalyAlarmActive() ? 1 : 0;
    tm[16] = (uint8_t)anomalyLastAlarmChannel();
    tm[17] = (uint8_t)(missionModelOrbitClock() + 0.5f);
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 18, true);
    return true;
  }
  if (sub == 1 && PL >= 2) { /* arm/disarm FDIR */
    fdirSetArmed(D[1] != 0);
    uint8_t tm[4] = {SPACECRAFT_ID, 1, (uint8_t)(D[1] ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 2) { /* force safe (attacker-visible injection point) */
    fdirForceSafe("REMOTE");
    uint8_t tm[4] = {SPACECRAFT_ID, 2, (uint8_t)fdirSafeActive(), '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 3) { /* exit safe */
    const char *reason = NULL;
    const bool ok = fdirRequestExit(&reason);
    uint8_t tm[4] = {SPACECRAFT_ID, 3, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    if (!ok && reason != NULL) {
      labTmError(reason);
    }
    return true;
  }
  if (sub == 4) { /* ack anomaly */
    fdirAckAnomaly();
    uint8_t tm[4] = {SPACECRAFT_ID, 4, (uint8_t)anomalyEnabled(),
                     (uint8_t)anomalyAlarmActive()};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 5 && PL >= 5) { /* FDICT_SET [5][idx][apid BE16][len][data] */
    const uint8_t idx = D[1];
    const uint16_t fapid = be16v_(D + 2);
    const uint8_t len = D[4];
    const bool ok = fdictSet(idx, fapid, D + 5, len);
    uint8_t tm[6] = {SPACECRAFT_ID, 5, idx, (uint8_t)(ok ? 1 : 0),
                     (uint8_t)(fdictHashLocked() ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 6, true);
    return true;
  }
  if (sub == 6) { /* FDICT_GET [6][idx] */
    fdict_entry_t e;
    uint8_t tm[40] = {SPACECRAFT_ID, 6, D[1]};
    if (fdictGet(D[1], &e)) {
      tm[2] = (uint8_t)(e.apid >> 8);
      tm[3] = (uint8_t)e.apid;
      tm[4] = e.len;
      memcpy(tm + 5, e.payload, e.len);
      labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, (uint16_t)(5 + e.len), true);
    } else {
      labTmError("FDICT IDX");
    }
    return true;
  }
  if (sub == 7) { /* burn hash */
    const bool ok = fdictHashSet();
    uint8_t tm[20] = {SPACECRAFT_ID, 7, (uint8_t)(ok ? 1 : 0)};
    memcpy(tm + 3, fdictHash(), 8);
    tm[11] = (uint8_t)(fdictHashLocked() ? 1 : 0);
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 12, true);
    return true;
  }
  if (sub == 8 && PL >= 2) { /* anomaly z (x10) */
    anomalySetZ(((float)D[1]) / 10.0f);
    uint8_t tm[4] = {SPACECRAFT_ID, 8, D[1], '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 9 && PL >= 2) { /* detumble on/off */
    missionModelDetumble(D[1] != 0);
    uint8_t tm[4] = {SPACECRAFT_ID, 9, (uint8_t)(D[1] ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 10 && PL >= 3) { /* mission time scale x10 */
    missionModelTimeScale(((float)be16v_(D + 1)) / 10.0f);
    uint8_t tm[4] = {SPACECRAFT_ID, 10, D[1], D[2]};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 11) { /* FDICT factory reset (harness prologue, V-20 parity) */
    fdictFactoryReset();
    uint8_t tm[4] = {SPACECRAFT_ID, 11, 1, '\0'};
    labTmSend(SPP_APID_TC_FDIR_CONFIG, tm, 4, true);
    return true;
  }
  labTmError("FDIR SUB?");
  return true;
}

static bool hSched(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("SCHED FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 0) { /* ADD [0][every u32 BE][apid BE16][len u8][payload] */
    if (PL < 8) {
      labTmError("SCHED ADD FORMAT");
      return true;
    }
    const uint32_t every = be32v_(D + 1);
    const uint16_t sapid = be16v_(D + 5);
    const uint8_t len = D[7];
    const bool ok = schedAdd(every, sapid, D + 8, len);
    uint8_t tm[6] = {SPACECRAFT_ID, 0, (uint8_t)(ok ? 1 : 0), schedCount(),
                     (uint8_t)(schedPersisted() ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_SCHED, tm, 6, true);
    return true;
  }
  if (sub == 1) { /* CLEAR */
    const bool ok = schedClear();
    uint8_t tm[5] = {SPACECRAFT_ID, 1, (uint8_t)(ok ? 1 : 0), schedCount(), '\0'};
    labTmSend(SPP_APID_TC_SCHED, tm, 5, true);
    return true;
  }
  if (sub == 2) { /* LIST */
    uint8_t tm[2 + SCHED_MAX_ENTRIES * (5 + 4)] = {SPACECRAFT_ID, 2};
    uint16_t off = 2;
    tm[off++] = schedCount();
    for (uint8_t i = 0; i < schedCount() && i < SCHED_MAX_ENTRIES; i++) {
      sched_entry_t e;
      if (schedGet(i, &e) && e.apid != 0xFFFF) {
        put16le_(&tm[off], (uint16_t)(e.every_s & 0xFFFF));
        off += 2;
        tm[off++] = (uint8_t)(e.apid >> 8);
        tm[off++] = (uint8_t)e.apid;
        tm[off++] = e.len;
      }
    }
    labTmSend(SPP_APID_TC_SCHED, tm, off, true);
    return true;
  }
  labTmError("SCHED SUB?");
  return true;
}

static bool hOta(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("OTA FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 0) { /* PUSH [0][off BE32][len u8][crc BE16][data] */
    if (PL < 8) {
      labTmError("OTA PUSH FORMAT");
      return true;
    }
    const uint32_t off = be32v_(D + 1);
    const uint8_t len = D[5];
    const uint16_t crc = be16v_(D + 6);
    const bool ok = otaPushChunk(off, D + 8, len, crc);
    uint8_t tm[5] = {SPACECRAFT_ID, 0, (uint8_t)(ok ? 1 : 0), 0, '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 5, true);
    return true;
  }
  if (sub == 1) { /* ACTIVATE */
    const bool ok = otaActivate();
    uint8_t tm[4] = {SPACECRAFT_ID, 1, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  if (sub == 2) { /* CONFIRM */
    const bool ok = otaConfirm();
    uint8_t tm[4] = {SPACECRAFT_ID, 2, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  if (sub == 3) { /* STATUS */
    fs_ota_status_t st;
    otaGetStatus(&st);
    uint8_t tm[32] = {SPACECRAFT_ID, 3, st.active_slot, st.pending_boot};
    tm[4] = st.boot_try_count;
    tm[5] = st.booted_slot;
    tm[6] = (uint8_t)(st.arwc >> 24);
    tm[7] = (uint8_t)(st.arwc >> 16);
    tm[8] = (uint8_t)(st.arwc >> 8);
    tm[9] = (uint8_t)st.arwc;
    tm[10] = st.arwc_enforce;
    tm[11] = st.sig_required;
    memcpy(tm + 12, st.image_sig, 8);
    memcpy(tm + 20, st.image_hash, 8);
    tm[28] = (uint8_t)(st.image_size >> 24);
    tm[29] = (uint8_t)(st.image_size >> 16);
    tm[30] = (uint8_t)(st.image_size >> 8);
    tm[31] = (uint8_t)st.image_size;
    labTmSend(SPP_APID_TC_OTA, tm, 32, true);
    return true;
  }
  if (sub == 4 && PL >= 5) { /* ARWC_SET (V-38: no authorisation) */
    const bool ok = otaArwcSet(be32v_(D + 1));
    uint8_t tm[4] = {SPACECRAFT_ID, 4, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  if (sub == 5) { /* ROLLBACK_A */
    const bool ok = otaRollbackToA();
    uint8_t tm[4] = {SPACECRAFT_ID, 5, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  if (sub == 6 && PL >= 14) { /* MANIFEST [6][sig8][arwc BE32][require] */
    const bool ok = otaManifest(D + 1, be32v_(D + 9), D[13]);
    uint8_t tm[4] = {SPACECRAFT_ID, 6, (uint8_t)(ok ? 1 : 0), '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  if (sub == 7 && PL >= 2) { /* ARWC_ENFORCE */
    fs_ota_status_t st;
    otaGetStatus(&st);
    st.arwc_enforce = (uint8_t)(D[1] ? 1 : 0);
    otaManifest(NULL, st.arwc, st.sig_required);
    uint8_t tm[4] = {SPACECRAFT_ID, 7, st.arwc_enforce, '\0'};
    labTmSend(SPP_APID_TC_OTA, tm, 4, true);
    return true;
  }
  labTmError("OTA SUB?");
  return true;
}

static bool hTcStats(space_packet_t *space_packet) {
  const uint8_t sub = (PL >= 1) ? D[0] : 0;
  if (sub == 1) {
    s_tc_rssi_sum = 0;
    s_tc_snr_sum = 0;
    s_tc_ferr_sum = 0;
    s_tc_count = 0;
    s_tc_rssi_min = 0;
    s_tc_rssi_max = 0;
    uint8_t tm[4] = {SPACECRAFT_ID, 1, 1, '\0'};
    labTmSend(SPP_APID_TC_TC_STATS, tm, 4, true);
    return true;
  }
  const uint8_t n = s_tc_count ? s_tc_count : 1;
  uint8_t tm[20] = {SPACECRAFT_ID, 0, s_tc_count};
  put16le_(tm + 3, (uint16_t)(int16_t)(int32_t)(s_tc_rssi_sum / n));
  put16le_(tm + 5, (uint16_t)(int16_t)(int32_t)(s_tc_snr_sum / n));
  put16le_(tm + 7, (uint16_t)(int16_t)(int32_t)(s_tc_ferr_sum / n));
  put16le_(tm + 9, (uint16_t)(int16_t)s_tc_rssi_min);
  put16le_(tm + 11, (uint16_t)(int16_t)s_tc_rssi_max);
  tm[13] = labDefenseBit(DEF_RADIO_CRC) ? 1 : 0;
  tm[14] = (uint8_t)(s_tc_last_apid >> 8);
  tm[15] = (uint8_t)s_tc_last_apid;
  put16le_(tm + 16, labTmCounter());
  labTmSend(SPP_APID_TC_TC_STATS, tm, 18, true);
  return true;
}

static bool hPadding(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("PAD FORMAT");
    return true;
  }
  covertSetPaddingMode(D[0]);
  uint8_t tm[6] = {SPACECRAFT_ID, covertPaddingMode(),
                   (uint8_t)(covertQueueDepth() >> 8),
                   (uint8_t)covertQueueDepth(), (uint8_t)labBeaconCloaked(),
                   '\0'};
  labTmSend(SPP_APID_TC_PADDING_CONFIG, tm, 6, true);
  return true;
}

static bool hCovert(space_packet_t *space_packet) {
  const bool ok = covertEnqueue(D, PL);
  uint8_t tm[8] = {SPACECRAFT_ID, (uint8_t)(ok ? 1 : 0),
                   (uint8_t)(covertQueueDepth() >> 8),
                   (uint8_t)covertQueueDepth(), covertPaddingMode(), 0, 0, '\0'};
  labTmSend(SPP_APID_TC_COVERT_ENQ, tm, 8, true);
  return true;
}

static bool hSnap(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("SNAP FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 1) { /* VCC_FREEZE [1][u8] */
    covertVccFreeze(D[1] != 0);
    uint8_t tm[6] = {SPACECRAFT_ID, 1, (uint8_t)(covertVccFrozen() ? 1 : 0),
                     (uint8_t)(covertVcc() >> 8), (uint8_t)covertVcc(), '\0'};
    labTmSend(SPP_APID_TC_PAYLOAD_SNAP, tm, 6, true);
    return true;
  }
  if (sub == 2) { /* DRAIN queue up to 64 B */
    uint8_t tm[2 + 64] = {SPACECRAFT_ID, 2};
    const uint16_t got = covertDequeue(tm + 3, 64);
    tm[2] = (uint8_t)got;
    labTmSend(SPP_APID_TC_PAYLOAD_SNAP, tm, (uint16_t)(3 + got), true);
    return true;
  }
  /* SNAP: 32-byte pseudo-image, enqueued for covert drain + direct TM */
  mission_model_t mm;
  missionModelGet(&mm);
  float t = 0, p = 0, alt = 0, hum = 0;
  extern bool bmeRead(float *, float *, float *, float *);
  bmeRead(&t, &p, &alt, &hum);

  uint8_t img[32];
  memset(img, 0, sizeof(img));
  memcpy(img, "IMG1", 4);
  const uint32_t ms = millis();
  img[4] = (uint8_t)ms;
  img[5] = (uint8_t)(ms >> 8);
  img[6] = (uint8_t)(ms >> 16);
  img[7] = (uint8_t)(ms >> 24);
  put16le_(img + 8, (uint16_t)(int16_t)(t * 100));
  put16le_(img + 10, (uint16_t)(p * 10));
  put16le_(img + 12, (uint16_t)(int16_t)(alt * 10));
  put16le_(img + 14, (uint16_t)(hum * 100));
  put16le_(img + 16, (uint16_t)(mm.tilt_dps * 100));
  put16le_(img + 18, (uint16_t)(mm.bus_voltage * 100));
  img[20] = (uint8_t)mm.battery_pct; /* float now (V-34): truncate == sim */
  put16le_(img + 21, labTmCounter());
  put16le_(img + 23, covertVcc());
  img[25] = mm.eclipse ? 1 : 0;
  img[26] = fdirSafeActive() ? 1 : 0;
  memcpy(img + 27, "PWN", 3);
  put16le_(img + 30, (uint16_t)(mm.power_w * 100));

  covertVccBump();
  uint8_t tm[3 + 32] = {SPACECRAFT_ID, 0,
                        (uint8_t)(covertVccFrozen() ? 1 : 0)};
  memcpy(tm + 3, img, 32);
  /* enqueue so it also flows out through the padding channel */
  covertEnqueue(img, 32);
  labTmSend(SPP_APID_TC_PAYLOAD_SNAP, tm, 35, true);
  return true;
}

static bool hHeater(space_packet_t *space_packet) {
  if (PL < 2) {
    labTmError("HEATER FORMAT");
    return true;
  }
  missionModelHeater(D[0], D[1] != 0);
  mission_model_t mm;
  missionModelGet(&mm);
  uint8_t tm[8] = {SPACECRAFT_ID, D[0], (uint8_t)(D[1] ? 1 : 0),
                   (uint8_t)mm.battery_pct}; /* float now (V-34): truncate */
  put16le_(tm + 4, (uint16_t)(mm.bus_voltage * 100));
  put16le_(tm + 6, (uint16_t)(mm.power_w * 100));
  labTmSend(SPP_APID_TC_HEATER, tm, 8, true);
  return true;
}

static bool hDefenses(space_packet_t *space_packet) {
  if (PL < 1) {
    labTmError("DEF FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 0 && PL >= 2) { /* SET flags bitmap */
    labDefenseSet(D[1]);
    uint8_t tm[4] = {SPACECRAFT_ID, 0, labDefenseFlags(), '\0'};
    labTmSend(SPP_APID_TC_DEFENSES_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 1) { /* GET */
    uint8_t tm[6] = {SPACECRAFT_ID, 1, labDefenseFlags(),
                     (uint8_t)tclCount(), (uint8_t)(tclEvicted() >> 8),
                     (uint8_t)tclEvicted()};
    labTmSend(SPP_APID_TC_DEFENSES_CONFIG, tm, 6, true);
    return true;
  }
  if (sub == 2 && PL >= 4) { /* LOG_DUMP [2][start BE16][count] */
    const uint16_t start = be16v_(D + 1);
    const uint8_t count = D[3];
    uint8_t tm[4 + 12 * 40];
    tm[0] = SPACECRAFT_ID;
    tm[1] = 2;
    tm[2] = (uint8_t)tclCount();
    tm[3] = 0; /* filled below */
    uint16_t off = 4;
    uint8_t got = 0;
    for (uint8_t i = 0; i < count; i++) {
      tclog_entry_t e;
      if (!tclRead((uint16_t)(start + i), &e)) {
        break;
      }
      memcpy(tm + off, &e.millis_stamp, 4);
      off += 4;
      tm[off++] = (uint8_t)(e.apid >> 8);
      tm[off++] = (uint8_t)e.apid;
      tm[off++] = (uint8_t)(e.seq >> 8);
      tm[off++] = (uint8_t)e.seq;
      tm[off++] = e.len;
      memcpy(tm + off, e.payload, e.len);
      off = (uint16_t)(off + e.len);
      got++;
      if (off > sizeof(tm) - 40) {
        break;
      }
    }
    tm[3] = got;
    labTmSend(SPP_APID_TC_DEFENSES_CONFIG, tm, off, true);
    return true;
  }
  if (sub == 3) { /* RESET to defaults */
    labDefenseSet(DEF_ANOMALY_EN);
    uint8_t tm[4] = {SPACECRAFT_ID, 3, labDefenseFlags(), '\0'};
    labTmSend(SPP_APID_TC_DEFENSES_CONFIG, tm, 4, true);
    return true;
  }
  if (sub == 4 && PL >= 2) { /* SB bus-auth toggle (CM0050 demo) */
    sbSetAuthEnabled(D[1] != 0);
    uint8_t tm[4] = {SPACECRAFT_ID, 4, sbAuthEnabled() ? 1 : 0, '\0'};
    labTmSend(SPP_APID_TC_DEFENSES_CONFIG, tm, 4, true);
    return true;
  }
  labTmError("DEF SUB?");
  return true;
}

/* ------------------------------------------------- lab harness services */
/* 0x26 LAB_STATUS: full internal state blob (the PoC transport uses this
 * over --usb; on the air it is also a deliberate info leak). Cleartext,
 * 53 bytes, little-endian. Mirrored field-for-field in the simulator. */
static bool hLabStatus(space_packet_t *space_packet) {
  (void)space_packet;
  uint8_t tm[53];
  mission_model_t mm;
  missionModelGet(&mm);
  fs_ota_status_t ota;
  otaGetStatus(&ota);
  gps_nav_t nav = {0};
  const bool fix = gpsRead(&nav);

  uint32_t flags = 0;
  flags |= labSecureLinkEnabled() ? 1u : 0u;
  flags |= labUsbDebugEnabled() ? 2u : 0u;
  flags |= labGsModeEnabled() ? 4u : 0u;
  flags |= labGsSessionActive() ? 8u : 0u;
  flags |= labPayloadArmed() ? 16u : 0u;

  uint32_t flags2 = 0;
  flags2 |= sdlsIsEnabled() ? 1u : 0u;
  flags2 |= sdlsArcRelaxed() ? 2u : 0u;
  flags2 |= mm.detumble_on ? 4u : 0u;
  flags2 |= mm.eclipse ? 8u : 0u;
  flags2 |= mm.brownout_armed ? 16u : 0u;

  uint32_t now = (uint32_t)millis();
  /* V-28: this is the ground station's clock sync point -- record the
   * mission clock value it is about to be told (same `now` the blob
   * carries), so the GS challenge can seed from the GS-side clock. */
  labMarkLabStatusSync(now);
  uint32_t bc = labBootCount();
  uint32_t chal = labGsChallengeValue();
  uint32_t rej = gpsRejectCount();
  uint32_t arc = sdlsArcValue();
  float bus_v = mm.bus_voltage;
  float power_w = mm.power_w;
  float tilt = mm.tilt_dps;

  uint16_t o = 0;
  tm[o++] = SPACECRAFT_ID;
  tm[o++] = 0; /* state: only "RUN" can ever answer on silicon */
  tm[o++] = (uint8_t)flags;
  tm[o++] = labMissionMode();
  tm[o++] = covertPaddingMode();
  tm[o++] = labDefenseFlags();
  tm[o++] = (uint8_t)(rej & 0xFF);
  tm[o++] = (uint8_t)((rej >> 8) & 0xFF);
  tm[o++] = nav.satellites;
  tm[o++] = fix ? 1 : 0;
  memcpy(tm + o, &bc, 4);
  o += 4;
  memcpy(tm + o, &now, 4);
  o += 4;
  memcpy(tm + o, &chal, 4);
  o += 4;
  memcpy(tm + o, &bus_v, 4);
  o += 4;
  memcpy(tm + o, ota.image_hash, 8);
  o += 8;
  tm[o++] = ota.pending_boot;
  tm[o++] = s_tc_count;
  memcpy(tm + o, &arc, 4);
  o += 4;
  tm[o++] = (uint8_t)flags2;
  tm[o++] = (uint8_t)mm.battery_pct; /* float now (V-34): truncate == sim */
  memcpy(tm + o, &power_w, 4);
  o += 4;
  memcpy(tm + o, &tilt, 4);
  o += 4;
  tm[o++] = 0;
  tm[o++] = 0;
  tm[o++] = 0;
  labTmSend(SPP_APID_TM_LAB_STATUS, tm, o, true);
  return true;
}

/* 0x27 LAB_CTRL: USB-only harness bridge.
 *   [0]=1 INJECT  [1]=rssi i8 [2]=snr u8dB [3..4]=ferr i16 [5]=stats-valid
 *                 [6]=inner apid [7..]=raw radio SPP frame
 *   [0]=2 POWERCYCLE (scratch wiped + reboot -- the power-event semantics)
 *   [0]=3 REBOOT (watchdog scratch survives -- the labReboot semantics)
 *   [0]=4 REARM (V-19 bench parity: cold-boot reference state for the
 *                 model/FDIR/schedule phase after a mid-PoC reset -- the
 *                 simulator's _cold_boot restarts its clock at the reset
 *                 instant; the board's real boot is ~5 s of model time)
 *   [0]=5 SYNC [1..4]=u32 LE ground-station mission clock (V-28 bench
 *                 parity: the harness injects its virtual window clock so
 *                 the GS challenge seeds from the same instant the PoC
 *                 predicts from -- see groundStationGenerateChallenge).
 *                 Also closes the FEED window (belt-and-braces: the window
 *                 self-terminates on its bench deadline).
 *   [0]=6 FEED_START [1..4]=u32 LE window length ms (V-19 bench parity:
 *                 opens the harness' advance() window -- the bench epoch
 *                 clock runs 1:1 with wall time only while the window is
 *                 open, and the mission model / FDIR / schedule / radio
 *                 workers advance only on that clock, exactly where the
 *                 simulator's _workers_tick does)  */
/* The 1 Hz FEED tick phase is declared before hLabCtrl: sub 4 (REARM)
 * pins it (s_anom_last_ms = now) so the first post-rearm FEED lands at
 * exactly now+1000 ms, like the simulator's cold-boot clock. */
static unsigned long s_anom_last_ms = 0;
static uint32_t s_tc_seen = 0;
static uint32_t s_tc_total = 0; /* V-24 diag: cumulative radio TC count */

/* V-19 bench parity: the FEED window (harness advance()). s_bench_ms is
 * the window-only EPOCH clock: it advances 1:1 with wall time only while
 * s_feed_active (sub 6 FEED_START .. sub 5 SYNC / bench deadline), and is
 * frozen across the inter-window TC phase -- exactly the simulator's
 * now_ms, which advances only inside advance(). The mission model, FDIR,
 * the schedule queue and the periodic radio workers are driven from it,
 * so they advance exactly where flatsat_sim.py _workers_tick does. The
 * window self-terminates after its deadline (the trailing SYNC write
 * arrives with USB latency and would otherwise keep the model running
 * past the window end the simulator never sees). */
static bool s_feed_active = false;
static uint32_t s_bench_ms = 0;
static uint32_t s_feed_deadline_ms = 0;
static unsigned long s_last_feed_ms = 0;
static uint32_t s_last_sched_s = 0; /* last bench second the queue ran on */

static bool hLabCtrl(space_packet_t *space_packet, command_source_t source) {
  if (source != COMMAND_SOURCE_USB) {
    labTmError("LAB USB ONLY");
    return true;
  }
  if (PL < 1) {
    labTmError("LAB FORMAT");
    return true;
  }
  const uint8_t sub = D[0];
  if (sub == 1) {
    if (PL < 7) {
      labTmError("LAB INJ FORMAT");
      return true;
    }
    if (D[5] & 1) {
      labRadioStatsOverride((int)(int8_t)D[1], (float)D[2],
                            (float)(int16_t)le16v_(D + 3), true);
    } else {
      labRadioStatsOverride(0, 0.0f, 0.0f, false);
    }
    uint8_t tm[4] = {SPACECRAFT_ID, 1, (uint8_t)(PL - 7), 'K'};
    labTmSend(SPP_APID_TM_LAB_CTRL, tm, 4, true);
    labInjectFrameAsRadio(D + 7, (uint16_t)(PL - 7));
    return true;
  }
  if (sub == 2) {
    labRebootBrownout(); /* ack + scratch wipe + reboot */
    return true;
  }
  if (sub == 3) {
    labReboot(); /* ack + reboot, scratch survives */
    return true;
  }
  if (sub == 4) {
    /* V-19 bench parity: the harness sends this right after the board
     * revives from a mid-PoC reset (0x02 / POWERCYCLE / REBOOT). Restore
     * the simulator's "just after RESETC" reference state:
     *   (1) thrusters back to the volatile idle power (10/10);
     *   (2) attitude reset (rate/euler/tilt 0, detumble off) -- the real
     *       boot integrated ~5 s of model time at the bench time scale;
     *   (3) FDIR cold re-arm WITHOUT the fdirRequestExit() release-window
     *       gate (the reset IS the re-arm, like _cold_boot);
     *   (4) schedule queue anchored to the next bench epoch (first FEED
     *       window after the re-arm): due at the epoch second -> first
     *       fire on the first epoch-second boundary, exactly like the
     *       simulator's due=now_ms//1000;
     *   (5) the 1 Hz FEED phase pinned (s_anom_last_ms = now) so that
     *       first tick lands at exactly now+1000 ms.
     * Secure link and watchdog scratch are deliberately untouched (the
     * V-21 cookie semantics must survive, and the post-reset secure-link
     * state already matches the simulator's cold-boot default). */
    thrusterSetT0Power(10);
    thrusterSetT1Power(10);
    missionModelRearmAttitude();
    fdirRearmColdBoot();
    schedRearm();
    s_anom_last_ms = millis();
    const uint8_t tm4[4] = {SPACECRAFT_ID, 4, 1, 'R'};
    labTmSend(SPP_APID_TM_LAB_CTRL, tm4, 4, true);
    return true;
  }
  if (sub == 5) {
    /* V-28 bench parity: see the header comment. The value becomes the
     * ground station's "last-synced mission clock" that
     * groundStationGenerateChallenge seeds from. Also closes the FEED
     * window (V-19): the harness writes it fire-and-forget at the window
     * end; the window usually already self-terminated on its bench
     * deadline, this is belt-and-braces for the write latency. */
    if (PL < 5) {
      labTmError("LAB SYNC FORMAT");
      return true;
    }
    uint32_t grid;
    memcpy(&grid, D + 1, 4);
    labMarkLabStatusSync(grid);
    s_feed_active = false;
    const uint8_t tm5[4] = {SPACECRAFT_ID, 5, 0, 'S'};
    labTmSend(SPP_APID_TM_LAB_CTRL, tm5, 4, true);
    return true;
  }
  if (sub == 6 && PL >= 5) {
    /* V-19 bench parity: open the harness' advance() window
     * (FEED_START [6][u32 LE window ms]). The bench epoch clock runs 1:1
     * with wall time only while s_feed_active, and the mission model /
     * FDIR / schedule queue / periodic radio workers advance only on
     * that clock -- the simulator's _workers_tick gating (its model
     * advances only inside advance()). The window self-terminates after
     * `win_ms` of bench time (the deadline is enforced in
     * labTickWorkers); the trailing SYNC (sub 5) closes it too. A
     * pending sched epoch (cold-boot replay / REARM) is consumed here:
     * the bench clock restarts at zero and the queue is due at the epoch
     * second, like the simulator's _cold_boot replay. */
    uint32_t win_ms;
    memcpy(&win_ms, D + 1, 4);
    if (schedEpochFeedStart()) {
      s_bench_ms = 0;
      s_last_sched_s = 0;
      missionModelTickReset();
      labResetRadioWorkerPhase();
    }
    s_feed_active = true;
    s_feed_deadline_ms = s_bench_ms + win_ms;
    s_last_feed_ms = millis();
    const uint8_t tm6[4] = {SPACECRAFT_ID, 6, 1, 'F'};
    labTmSend(SPP_APID_TM_LAB_CTRL, tm6, 4, true);
    return true;
  }
  labTmError("LAB SUB?");
  return true;
}

/* ------------------------------------------------------- tick workers */

/* V-24 bench parity: the anomaly detector's TC-rate channel samples the
 * number of RADIO-sourced telecommands of the last second, exactly like
 * the reference model (flatsat_sim.py tc_seen, radio-stats block). The
 * counter is fed from commandApidHandler for radio-source TCs only and
 * consumed (and cleared) by the 1 Hz feed below. */
void labCountRadioTc(void) {
  s_tc_seen++;
  s_tc_total++;
}

bool labFeedActive(void) {
  return s_feed_active;
}

uint32_t labBenchMs(void) {
  return s_bench_ms;
}

void labTickWorkers(void) {
  const unsigned long now = millis();
  /* V-19 bench parity: advance the bench epoch clock 1:1 with wall time
   * while the FEED window is open (frozen otherwise) and self-terminate
   * the window on its bench deadline -- the simulator's model clock stops
   * exactly when advance() returns, so the board's model time must stop
   * there too (the trailing SYNC write arrives with USB latency and
   * would otherwise keep the model running past the window end). */
  if (s_feed_active) {
    s_bench_ms += (uint32_t)(now - s_last_feed_ms);
    s_last_feed_ms = now;
    if (s_bench_ms >= s_feed_deadline_ms) {
      s_feed_active = false;
    }
  } else {
    s_last_feed_ms = now;
  }

  missionModelTick();
  fdirTick();

  /* V-19 bench parity: run the queue on the bench-second boundaries,
   * like the simulator's _sched_due on the model-second grid inside
   * advance() (it used to ride the 1 Hz anomaly block below, which is
   * real-time and would fire the queue outside the windows). */
  if (s_feed_active && s_bench_ms / 1000UL != s_last_sched_s) {
    s_last_sched_s = s_bench_ms / 1000UL;
    schedRunDue(s_last_sched_s);
  }

  if (now - s_anom_last_ms >= 1000UL) {
    s_anom_last_ms = now;
    mission_model_t mm;
    missionModelGet(&mm);
    anomalyFeed(ANOM_CH_TILT, mm.tilt_dps);
    anomalyFeed(ANOM_CH_POWER, mm.power_w);
    anomalyFeed(ANOM_CH_BUS_V, mm.bus_voltage * 100.0f);
    anomalyFeed(ANOM_CH_TC_RATE, (float)s_tc_seen);
#if defined(ARDUINO_ARCH_RP2040)
    /* Bench diagnostic (V-24): the exact per-second input sequence the
     * on-board EWMA sees (tc = radio TCs since the previous feed). Lets
     * the board's channel state be diffed 1:1 against the reference
     * model's tc_seen sequence. */
    Serial.printf("[LAB] FEED ms=%lu tc=%lu tot=%lu tilt=%ld pw100=%ld "
                  "bus100=%ld alarm=%d ch=%d maxms=%u maxtag=%s slow=%lu\n",
                  (unsigned long)now, (unsigned long)s_tc_seen,
                  (unsigned long)s_tc_total,
                  (long)(mm.tilt_dps * 100.0f),
                  (long)(mm.power_w * 100.0f),
                  (long)(mm.bus_voltage * 100.0f),
                  anomalyAlarmActive() ? 1 : 0,
                  (int)anomalyLastAlarmChannel(),
                  (unsigned)s_loop_max_ms, s_loop_max_tag,
                  (unsigned long)s_loop_slow_cnt);
    s_loop_max_ms = 0;
    s_loop_slow_cnt = 0;
#endif
    s_tc_seen = 0;
    /* The schedule queue runs on the bench-second boundaries above
     * (V-19 bench parity), not on this real-time 1 Hz feed. */
  }
}
