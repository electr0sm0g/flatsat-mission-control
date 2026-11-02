/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
using std::size_t;
inline unsigned long millis(void) { return 0; }
struct SerialShim {
  void printf(const char *f, ...) { (void)f; }
  void print(const char *s) { (void)s; }
  void println(const char *s) { (void)s; }
  void println(void) {}
  void println(int v) { (void)v; }
  void write(const uint8_t *b, size_t l) { (void)b; (void)l; }
  void write(uint8_t c) { (void)c; }
  void print(int v) { (void)v; }
  void print(unsigned v) { (void)v; }
  void print(unsigned long v) { (void)v; }
  void println(unsigned v) { (void)v; }
  void println(unsigned long v) { (void)v; }
  int available(void) { return 0; }
  int read(void) { return -1; }
  size_t availableForWrite(void) { return 4096; }
};
inline void delay(unsigned long ms) { (void)ms; }
inline float radians(float d) { return d * 0.017453292519943295f; }
extern SerialShim Serial;
