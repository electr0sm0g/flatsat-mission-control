/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <cstdint>
struct watchdog_hw_t { volatile uint32_t scratch[8]; };
extern watchdog_hw_t s_wdt_hw;
#define watchdog_hw (&s_wdt_hw)
inline void watchdog_reboot(uint32_t a, uint32_t b, uint32_t c) { (void)a; (void)b; (void)c; }
inline void watchdog_enable(uint32_t a, bool b) { (void)a; (void)b; }
