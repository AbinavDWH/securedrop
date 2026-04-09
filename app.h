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

#ifndef APP_H
#define APP_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>

#include <gtk/gtk.h>
#include <microhttpd.h>

/* ── Constants ─────────────────────────────────────────────── */
#define APP_NAME            "Veil-Xfer"
#define APP_VERSION         "5.0.0"
#define CHUNK_SIZE          (512 * 1024)
#define AES_KEY_LEN         32
#define AES_IV_LEN          12
#define AES_TAG_LEN         16
#define MASTER_KEY_LEN      32
#define SALT_LEN            32
#define HASH_LEN            32
#define RSA_KEY_BITS        4096
#define SERVER_PORT         8443
#define PBKDF2_ITERATIONS   1000000
#define RATE_LIMIT_MAX_FAILS  5
#define RATE_LIMIT_LOCKOUT_SEC 60
#define MAX_RATE_ENTRIES      256
#define P2P_DEFAULT_PORT    9900
#define FILE_ID_HEX_LEN     64
#define MAX_FILES           256
#define MAX_STORED_FILES    1024
#define MAX_TOR_CIRCUITS    8
#define MAX_CHUNKS          8192

/* ═══════════════════════════════════════════════════════════════
 * SUB-SERVER PORT CONFIGURATION
 *
 *   Main server:  port 8443
 *   Sub-servers:  ports 10000 – 10999  (1000 max)
 *
 *   Each sub-server stores encrypted chunks independently.
 *   Chunks are distributed round-robin across active sub-servers.
 * ═══════════════════════════════════════════════════════════════ */
#define SUB_PORT_BASE       10000              /* First sub-server port  */
#define SUB_PORT_MAX        10127              /* Last sub-server port   */
#define MAX_SUB_SERVERS     128                /* 10000 to 10127         */

/* ── Directories ───────────────────────────────────────────── */
#define VAULT_DIR           "secure_vault"
#define STORE_DIR           "chunk_store"
#define KEY_DIR             "keys"
#define RSA_PUB_FILE        "keys/node_pub.pem"
#define RSA_PRIV_FILE       "keys/node_priv.pem"
#define OUTPUT_DIR          "received_files"
#define META_DIR            "file_meta"
#define TOR_DATA_DIR        "tor_data"
#define TOR_HS_DIR          "tor_data/hidden_service"
#define ONION_VIRTUAL_PORT  80
#define ONION_TIMEOUT_SEC   120

/* ── Mode / Log targets ────────────────────────────────────── */
enum {
    MODE_SHARE    = 0,
    MODE_RECEIVE  = 1,
    MODE_SEND     = 2,
    MODE_VAULT    = 3,
    MODE_SERVER   = 4,
    MODE_P2P      = 5,
    MODE_ADVANCED = 6
};
enum {
    LOG_SHARE    = 0,
    LOG_RECV     = 1,
    LOG_SEND     = 2,
    LOG_VAULT    = 3,
    LOG_SERVER   = 4,
    LOG_P2P      = 5,
    LOG_ADVANCED = 6
};

/* ── Tree-view columns (file lists) ────────────────────────── */
enum {
    COL_ICON = 0,
    COL_NAME,
    COL_SIZE,
    COL_PATH,
    COL_STATUS,
    COL_ID,
    NUM_COLS
};



/* ── Tree-view columns ─────────────────────────────────────── */
enum {
    SUBCOL_INDEX = 0,
    SUBCOL_PORT,
    SUBCOL_ONION,
    SUBCOL_STATUS,
    SUBCOL_CHUNKS,
    SUBCOL_ENABLED,
    SUBCOL_NUM
};



/* ── Data structures ───────────────────────────────────────── */

typedef struct {
    char   path[4096];
    char   name[512];
    size_t size;
    int    is_dir;
} FileItem;

typedef struct {
    unsigned char *data;
    size_t         len;
    size_t         cap;
} Buf;

/* One sub-server (runs on same host, different port) */
typedef struct {
    char   address[256];
    int    port;
    int    active;
    int    chunk_count;
    struct MHD_Daemon *daemon;
    /* Independent Tor hidden service per sub-server */
    char   onion_addr[128];
    pid_t  tor_pid;
    char   tor_datadir[256];
    int    tor_ready;
} SubServer;

/* Metadata for a file stored on the server */
typedef struct {
    char          file_id[FILE_ID_HEX_LEN + 1];
    char          original_name[512];
    size_t        original_size;
    uint32_t      chunk_count;

    unsigned char password_salt[SALT_LEN];
    unsigned char password_verify[HASH_LEN];

    unsigned char enc_master_key[512];
    size_t        emk_len;
    unsigned char enc_rsa_priv[8192];
    size_t        erp_len;
    unsigned char rsa_priv_iv[AES_IV_LEN];
    unsigned char rsa_priv_tag[AES_TAG_LEN];
    unsigned char rsa_pub_pem[4096];
    size_t        rsa_pub_len;

    time_t        upload_time;
    int           distributed;
    int           chunk_locations[MAX_CHUNKS];
} StoredFileMeta;

/* Tor circuit info */
typedef struct {
    int  port;
    int  active;
    char proxy[128];
} TorCircuit;

/* Onion hidden service state */
typedef struct {
    pid_t  tor_pid;
    char   onion_address[128];
    char   full_address[256];
    char   data_dir[512];
    char   torrc_path[512];
    int    virtual_port;
    int    local_port;
    int    running;
} OnionService;

/* ── Main application state ────────────────────────────────── */
typedef struct {
    GtkWidget *window, *header_bar, *main_stack;
    GtkWidget *sidebar;
    GtkWidget *mode_btns[7];
    int        current_mode;
    guint      server_anim_timer;
    int        server_anim_phase;

    /* Share page */
    GtkWidget     *share_page, *share_file_list;
    GtkWidget     *share_drag_area, *share_file_scroll;
    GtkListStore  *share_store;
    GtkWidget     *share_add_btn, *share_add_folder_btn;
    GtkWidget     *share_remove_btn, *share_clear_btn;
    GtkWidget     *share_start_btn, *share_stop_btn;
    GtkWidget     *share_status_box, *share_addr_label;
    GtkWidget     *share_server_badge;
    GtkWidget     *share_copy_btn, *share_dl_label;
    GtkWidget     *share_progress, *share_log_view;
    GtkWidget     *share_password_entry;
    GtkTextBuffer *share_log_buf;

    /* Receive page */
    GtkWidget     *recv_page;
    GtkWidget     *recv_server_entry;
    GtkWidget     *recv_fileid_entry;
    GtkWidget     *recv_password_entry;
    GtkWidget     *recv_fetch_btn;
    GtkWidget     *recv_progress, *recv_log_view;
    GtkTextBuffer *recv_log_buf;

    /* Send page */
    GtkWidget     *send_page, *send_file_btn;
    GtkWidget     *send_addr_entry;
    GtkWidget     *send_password_entry;
    GtkWidget     *send_btn, *send_progress, *send_log_view;
    GtkWidget     *send_circuit_label;
    GtkWidget     *send_fileid_label;
    GtkTextBuffer *send_log_buf;

    /* Vault page */
    GtkWidget     *vault_page, *vault_list;
    GtkWidget     *vault_add_btn, *vault_export_btn;
    GtkWidget     *vault_delete_btn;
    GtkWidget     *vault_log_view;
    GtkListStore  *vault_store;
    GtkTextBuffer *vault_log_buf;

    /* Server page */
        GtkWidget     *server_page;
    GtkWidget     *server_start_btn, *server_stop_btn;
    GtkWidget     *server_files_list;
    GtkListStore  *server_files_store;
    GtkWidget     *server_log_view;
    GtkWidget     *server_subserver_entry;
    GtkWidget     *server_add_sub_btn;
    GtkWidget     *server_batch_entry;
    GtkWidget     *server_batch_btn;
    GtkWidget     *server_stats_label;
    GtkTextBuffer *server_log_buf;

    GtkWidget     *server_tor_count_entry;
    GtkWidget     *server_tor_start_btn;
    GtkWidget     *server_tor_stop_btn;
    GtkWidget     *server_sub_list;
    GtkListStore  *server_sub_store;
    int            user_tor_count;
    /* Onion GUI */
    GtkWidget     *server_onion_label;
    GtkWidget     *server_onion_copy_btn;
    GtkWidget     *server_onion_status;
    GtkWidget     *server_onion_frame;

    /* Server daemon */
    struct MHD_Daemon *server_daemon;
    volatile int       server_running;
    volatile int       download_count;
    volatile int       upload_count;

    /* Distributed storage — up to 1000 sub-servers */
    SubServer      *sub_servers;               /* heap-allocated array  */
    int             num_sub_servers;
    int             sub_servers_cap;            /* allocated capacity    */
    pthread_mutex_t subserver_mutex;

    /* Stored files metadata */
    StoredFileMeta *stored_files;
    int stored_file_count;
    int stored_files_cap;
    pthread_mutex_t stored_mutex;

    /* Tor circuits */
    TorCircuit      circuits[MAX_TOR_CIRCUITS];
    int             num_circuits;
    int             next_circuit;
    pthread_mutex_t circuit_mutex;

    /* Files for sharing */
    FileItem        files[MAX_FILES];
    int             file_count;
    pthread_mutex_t file_mutex;

    /* Onion service */
    OnionService    onion;

    /* P2P page */
    GtkWidget     *p2p_page;
    GtkWidget     *p2p_send_file_btn, *p2p_send_password_entry;
    GtkWidget     *p2p_send_subs_entry;          /* NEW: number of sub-servers */
    GtkWidget     *p2p_start_btn, *p2p_stop_btn;
    GtkWidget     *p2p_send_status_label;
    GtkWidget     *p2p_recv_addr_entry, *p2p_recv_password_entry;
    GtkWidget     *p2p_recv_btn;
    GtkWidget     *p2p_progress, *p2p_log_view;
    GtkTextBuffer *p2p_log_buf;

    /* Advanced page */
    GtkWidget     *adv_page;
    GtkWidget     *adv_chunks_per_sub_entry;
    GtkWidget     *adv_retry_timeout_entry;
    GtkWidget     *adv_max_retries_entry;
    GtkWidget     *adv_thread_count_entry;
    GtkWidget     *adv_warmup_stagger_entry;
    GtkWidget     *adv_apply_btn, *adv_reset_btn;
    GtkWidget     *adv_log_view;
    GtkTextBuffer *adv_log_buf;

    GtkCssProvider *css;
} App;

extern App app;

#endif /* APP_H */