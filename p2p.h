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

#ifndef P2P_H
#define P2P_H

#include "app.h"

/* ══════════════════════════════════════════════════════════════
 * P2P v2 — Parallel Tor Transfer
 *
 * Uses the same protocol/crypto as server mode:
 *   - Chunked AES-256-GCM encryption
 *   - HKDF per-chunk key derivation
 *   - RSA-4096 key wrapping
 *   - PBKDF2-1M password protection
 *
 * Adds:
 *   - Local sub-servers for chunk distribution
 *   - Per-sub-server Tor hidden services
 *   - Parallel download via Tor circuit pool
 *   - Onion-only mode (no clearnet exposure)
 * ══════════════════════════════════════════════════════════════ */

#define P2P_MAIN_PORT       9800
#define P2P_SUB_PORT_BASE   10200
#define P2P_SUB_PORT_MAX    10327
#define P2P_MAX_SUBS        128
#define P2P_DEFAULT_SUBS    8
#define P2P_CHUNK_SIZE      CHUNK_SIZE   /* 512KB, same as server */
#define P2P_ONION_TIMEOUT   180

/* P2P sub-server state */
typedef struct {
    int                port;
    int                active;
    struct MHD_Daemon *daemon;
    char               onion_addr[128];
    pid_t              tor_pid;
    char               tor_datadir[256];
    int                tor_ready;
} P2PSubServer;

/* P2P sender state — stored in App or standalone */
typedef struct {
    /* Encrypted payload (full protocol format) */
    unsigned char     *payload;
    size_t             payload_len;
    char               file_id[FILE_ID_HEX_LEN + 1];

    /* Chunk index for sub-server storage */
    uint32_t           chunk_count;
    size_t            *chunk_offsets;    /* offset into payload */
    uint32_t          *chunk_sizes;     /* wire size per chunk */
    size_t             header_len;      /* metadata portion    */

    /* File info */
    char               filename[512];
    size_t             filesize;

    /* Password verification */
    unsigned char      pw_salt[SALT_LEN];
    unsigned char      pw_verify[HASH_LEN];

    /* Sub-servers */
    P2PSubServer       subs[P2P_MAX_SUBS];
    int                num_subs;
    pthread_mutex_t    subs_mutex;

    /* Main server */
    struct MHD_Daemon *main_daemon;
    volatile int       running;

    /* Tor for main endpoint */
    pid_t              main_tor_pid;
    char               main_onion[256];
    char               main_tordata[256];
    int                main_tor_ready;

    pthread_mutex_t    mutex;
} P2PState;

/* Start P2P sender: encrypt, chunk, distribute, create .onions */
void p2p_start_sender(const char *filepath,
                      const char *password,
                      int num_subs,
                      int log_target);

/* Stop the P2P sender (kill Tor, stop sub-servers) */
void p2p_stop_sender(int log_target);

/* Receive a file from a P2P sender via Tor */
void p2p_receive_file(const char *onion_addr,
                      const char *password,
                      int log_target);

/* Query state */
int  p2p_is_running(void);
const char *p2p_get_onion_address(void);

#endif /* P2P_H */