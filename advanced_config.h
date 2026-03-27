/*
 * SecureDrop — Encrypted File Sharing over Tor
 * Copyright (C) 2026  Abinav
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ADVANCED_CONFIG_H
#define ADVANCED_CONFIG_H

/* ══════════════════════════════════════════════════════════════
 * Advanced Configuration — runtime-tunable parameters
 *
 * All fields have sensible defaults. The Advanced GUI page
 * lets the user tweak these; validation ensures no bad values.
 * Settings persist to ~/.config/securedrop/advanced.conf
 * ══════════════════════════════════════════════════════════════ */

typedef struct {
    int chunks_per_sub;      /* 1–8,   default 1   */
    int retry_timeout_sec;   /* 15–300, default 60  */
    int max_retries;         /* 1–10,  default 4    */
    int download_threads;    /* 0=auto, 1–128       */
    int warmup_stagger_ms;   /* 100–5000, default 500 */
} AdvancedConfig;

/* Global instance */
extern AdvancedConfig adv_config;

/* Reset all fields to compile-time defaults */
void adv_config_reset(void);

/* Clamp a single value to [lo, hi]; returns clamped value */
int adv_config_clamp(int val, int lo, int hi);

/* Save current config to ~/.config/securedrop/advanced.conf */
int adv_config_save(void);

/* Load config from file (call before gui_build) */
int adv_config_load(void);

#endif /* ADVANCED_CONFIG_H */
