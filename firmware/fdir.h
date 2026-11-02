/*  - fdir.h
 *
 * flatsat-lab vulnerable firmware v2 -- fault detection / isolation and
 * recovery + the contingency dictionary (V-20 / V-22, the embedded twin of
 * the OPS-SAT `executable.jar` supervisor backdoor, course ch.9.1/9.2).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef FIRMWARE_FDIR_H
#define FIRMWARE_FDIR_H
#include <Arduino.h>

#define FDIR_TILT_ALARM_DPS 5.0f /* SV-MA-2 tumbling threshold */
#define FDIR_BUS_SAFE_V 22.0f
#define FDIR_RELEASE_WINDOW_MS 120000UL /* course: < 2 min release window */

void fdirBootDefaults(void);
void fdirTick(void);

bool fdirArmed(void);
void fdirSetArmed(bool on);
bool fdirSafeActive(void);
unsigned long fdirSafeEntryMs(void);
uint32_t fdirTriggerCount(void);
const char *fdirLastTrigger(void);

/* EX-0006 relaxations while safe mode is active: */
bool fdirTestmode(void);   /* accept TEST APIDs 0xF0-0xFF */
bool fdirSafeForceEcb(void); /* CCM/CTR suites downgraded to ECB in safe */

/* manual exit (FDIR_CONFIG sub 3): only honoured once the release window
 * elapsed AND all triggers cleared -- mirrors real FDIR tables. */
bool fdirRequestExit(const char **reason);
/* V-19 bench parity: the harness REARM (LAB_CTRL sub 4) restores the
 * cold-boot FDIR reference (safe cleared, tilt debounce zeroed) without
 * the fdirRequestExit() release-window / trigger gates -- the reset IS
 * the re-arm, like flatsat_sim.py _cold_boot (fdir_safe=False, fdir_armed
 * =True, tilt_over_since=0). */
void fdirRearmColdBoot(void);
/* inject a safe-mode entry remotely (defence evasion demos): */
void fdirForceSafe(const char *cause);

/* acknowledgement clears the latched anomaly bit */
void fdirAckAnomaly(void);

#endif // FIRMWARE_FDIR_H
