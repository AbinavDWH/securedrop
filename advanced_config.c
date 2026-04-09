/*
 * Veil-Xfer — Encrypted File Sharing over Tor
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

#include "advanced_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>

/* ══════════════════════════════════════════════════════════════
 * DEFAULTS
 * ══════════════════════════════════════════════════════════════ */

#define ADV_DEF_CHUNKS_PER_SUB    1
#define ADV_DEF_RETRY_TIMEOUT     60
#define ADV_DEF_MAX_RETRIES       4
#define ADV_DEF_DOWNLOAD_THREADS  0   /* 0 = auto */
#define ADV_DEF_WARMUP_STAGGER    500

AdvancedConfig adv_config = {
    .chunks_per_sub    = ADV_DEF_CHUNKS_PER_SUB,
    .retry_timeout_sec = ADV_DEF_RETRY_TIMEOUT,
    .max_retries       = ADV_DEF_MAX_RETRIES,
    .download_threads  = ADV_DEF_DOWNLOAD_THREADS,
    .warmup_stagger_ms = ADV_DEF_WARMUP_STAGGER,
};

void adv_config_reset(void)
{
    adv_config.chunks_per_sub    = ADV_DEF_CHUNKS_PER_SUB;
    adv_config.retry_timeout_sec = ADV_DEF_RETRY_TIMEOUT;
    adv_config.max_retries       = ADV_DEF_MAX_RETRIES;
    adv_config.download_threads  = ADV_DEF_DOWNLOAD_THREADS;
    adv_config.warmup_stagger_ms = ADV_DEF_WARMUP_STAGGER;
}

int adv_config_clamp(int val, int lo, int hi)
{
    if (val < lo) return lo;
    if (val > hi) return hi;
    return val;
}

/* ══════════════════════════════════════════════════════════════
 * CONFIG FILE PATH
 * ══════════════════════════════════════════════════════════════ */

#define CONFIG_DIR_NAME   "Veil-Xfer"
#define CONFIG_FILE_NAME  "advanced.conf"
#define MAX_PATH_LEN      512
#define MAX_LINE_LEN      256

/* Build config file path: ~/.config/Veil-Xfer/advanced.conf
   Returns 0 on success, -1 on failure. */
static int config_path(char *out, size_t outsz)
{
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home || !home[0]) return -1;

    int n = snprintf(out, outsz,
        "%s/.config/%s/%s",
        home, CONFIG_DIR_NAME, CONFIG_FILE_NAME);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

/* Ensure parent directory exists */
static int ensure_config_dir(void)
{
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home || !home[0]) return -1;

    char dir[MAX_PATH_LEN];

    /* ~/.config */
    snprintf(dir, sizeof(dir), "%s/.config", home);
    mkdir(dir, 0755);

    /* ~/.config/Veil-Xfer */
    snprintf(dir, sizeof(dir),
        "%s/.config/%s", home, CONFIG_DIR_NAME);
    mkdir(dir, 0700);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * SAVE
 * ══════════════════════════════════════════════════════════════ */

int adv_config_save(void)
{
    if (ensure_config_dir() != 0)
        return -1;

    char path[MAX_PATH_LEN];
    if (config_path(path, sizeof(path)) != 0)
        return -1;

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "# Veil-Xfer Advanced Configuration\n");
    fprintf(f, "# Auto-generated — edit with care\n\n");
    fprintf(f, "chunks_per_sub=%d\n",
        adv_config.chunks_per_sub);
    fprintf(f, "retry_timeout_sec=%d\n",
        adv_config.retry_timeout_sec);
    fprintf(f, "max_retries=%d\n",
        adv_config.max_retries);
    fprintf(f, "download_threads=%d\n",
        adv_config.download_threads);
    fprintf(f, "warmup_stagger_ms=%d\n",
        adv_config.warmup_stagger_ms);

    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * LOAD
 * ══════════════════════════════════════════════════════════════ */

/* Safe integer parse: returns 1 on success */
static int safe_atoi(const char *s, int *out)
{
    if (!s || !*s) return 0;

    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0')
        return 0;
    if (v < -999999 || v > 999999)
        return 0;

    *out = (int)v;
    return 1;
}

int adv_config_load(void)
{
    char path[MAX_PATH_LEN];
    if (config_path(path, sizeof(path)) != 0)
        return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;   /* No config file yet — use defaults */

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';

        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\0')
            continue;

        /* Split key=value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        int v;
        if (!safe_atoi(val, &v)) continue;

        if (strcmp(key, "chunks_per_sub") == 0)
            adv_config.chunks_per_sub =
                adv_config_clamp(v, 1, 8);
        else if (strcmp(key, "retry_timeout_sec") == 0)
            adv_config.retry_timeout_sec =
                adv_config_clamp(v, 15, 300);
        else if (strcmp(key, "max_retries") == 0)
            adv_config.max_retries =
                adv_config_clamp(v, 1, 10);
        else if (strcmp(key, "download_threads") == 0)
            adv_config.download_threads =
                adv_config_clamp(v, 0, 128);
        else if (strcmp(key, "warmup_stagger_ms") == 0)
            adv_config.warmup_stagger_ms =
                adv_config_clamp(v, 100, 5000);
        /* Unknown keys are silently ignored */
    }

    fclose(f);
    return 0;
}
