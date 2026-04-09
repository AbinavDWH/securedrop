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

#ifndef TOR_POOL_H
#define TOR_POOL_H

#include "app.h"

#define TOR_POOL_MAX        128
#define TOR_POOL_BASE_PORT  9060
#define TOR_POOL_TIMEOUT    90

typedef struct {
    pid_t pid;
    int   socks_port;
    char  proxy[128];
    char  data_dir[512];
    int   ready;
} TorPoolEntry;

typedef struct {
    TorPoolEntry    entries[TOR_POOL_MAX];
    int             count;
    int             next;
    pthread_mutex_t mutex;
    int             initialized;
    int             matched_to_servers;
} TorPool;

/* Start N independent Tor SOCKS5 proxies */
int tor_pool_start(int count, int log_target);

/* Get proxy URL by index */
const char *tor_pool_get_proxy(int index);

/* Round-robin next proxy */
const char *tor_pool_next_proxy(void);

/* How many are ready */
int tor_pool_ready_count(void);

/* Build array of proxy strings for parallel use */
int tor_pool_get_all_proxies(const char **out,
                             int max_out);

/* Stop all Tor instances */
void tor_pool_stop(int log_target);

#endif /* TOR_POOL_H */