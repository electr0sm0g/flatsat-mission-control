/*  - extcmds.h
 *
 * flatsat-lab vulnerable firmware v2 -- extension telecommand dispatcher.
 * One entry point is called from worker.cpp's commandApidHandler() before
 * the unknown-APID fallback; all v2 APIDs (0x14..0x25 + the TEST window)
 * live here, keeping the upstream file diff minimal.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_EXTCMDS_H
#define FIRMWARE_EXTCMDS_H
#include "labhooks.h"
#include "mission.h"
#include "spp.h"
#include <Arduino.h>

/* Returns true when the APID was handled (extension or TEST window). */
bool extCommandHandler(space_packet_t *space_packet, uint16_t apid,
                       command_source_t source);

/* Called at the top of telemetryRadioWorker(): mission model, FDIR,
 * anomaly feeds, schedule replay. */
void labTickWorkers(void);

/* Uplink statistics hook (V-03/V-29): called from the radio receive path
 * with the SX1262 per-packet figures. */
void labTcStatsNote(int rssi, float snr, float freq_error, uint16_t apid_guess);

/* Defence flags (DEFENSES_CONFIG). */
uint8_t labDefenseFlags(void);
void labDefenseSet(uint8_t flags);
bool labDefenseBit(uint8_t bit);

/* beacon cloak helper (CM0006 defence bit) */
bool labBeaconCloaked(void);

#endif // FIRMWARE_EXTCMDS_H
