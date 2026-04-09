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

#ifndef STORAGE_H
#define STORAGE_H

#include "app.h"
#include "util.h"

#include <microhttpd.h>

#define STORE_DIR      "chunk_store"
#define META_DIR       "file_meta"
#define OUTPUT_DIR     "received_files"

// #define SUB_PORT_BASE  9100
// #define SUB_PORT_MAX   9999
// #define MAX_SUB_SERVERS 256

/* ── Init ─────────────────────────────────────── */
void storage_init(void);

/* ── Chunk storage ────────────────────────────── */
int storage_store_chunk(const char *file_id,
                        uint32_t chunk_idx,
                        const unsigned char *data,
                        size_t len,
                        int log_target);

/* Parallel batch store — server-side */
int storage_store_chunks_parallel(
    const char *file_id,
    int chunk_count,
    const unsigned char **chunk_data,
    const size_t *chunk_lens,
    int *chunk_locations_out,
    int log_target);

int storage_retrieve_chunk(const char *file_id,
                           uint32_t chunk_idx,
                           int sub_server_idx,
                           Buf *out,
                           int log_target);

/* ── Port validation ──────────────────────────── */
int storage_validate_port(int port);

/* ── Metadata persistence ─────────────────────── */
int storage_save_meta(const StoredFileMeta *meta,
                      int log_target);
int storage_load_meta(const char *file_id,
                      StoredFileMeta *meta_out);
int storage_load_all_meta(int log_target);
int storage_delete_file(const char *file_id,
                        int log_target);

/* ── Sub-server management ────────────────────── */
int  storage_add_subserver(const char *address,
                           int port,
                           int log_target);
int  storage_add_subservers_batch(int count,
                                  int log_target);
int  storage_start_subserver(int index,
                             int log_target);
void storage_start_all_subservers(int log_target);
void storage_stop_subservers(void);
int  storage_active_subserver_count(void);

/* ── Sub-server HTTP handler ──────────────────── */
enum MHD_Result subserver_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls);


int storage_active_subserver_count(void);

int ensure_stored_capacity(void);



#endif /* STORAGE_H */