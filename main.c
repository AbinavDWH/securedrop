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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <gtk/gtk.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "app.h"
#include "gui.h"
#include "tor.h"
#include "storage.h"
#include "onion.h"
#include "tor_pool.h"
#include "p2p.h"
#include "advanced_config.h"

/* ── Global application state ──────────────────────────────── */

App app;

/* ── Signal handler for clean shutdown ─────────────────────── */

static void signal_handler(int sig)
{
    (void)sig;
    fprintf(stderr, "\n[Veil-Xfer] Shutting down...\n");
    gtk_main_quit();
}

/* ── Main ──────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* Initialize GTK */
    gtk_init(&argc, &argv);

    /* Initialize curl */
    curl_global_init(CURL_GLOBAL_ALL);

    /* Initialize OpenSSL */
    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS |
        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    /* Clear application state */
    memset(&app, 0, sizeof(app));

    /* Initialize mutexes */
    pthread_mutex_init(&app.file_mutex, NULL);
    pthread_mutex_init(&app.circuit_mutex, NULL);
    pthread_mutex_init(&app.stored_mutex, NULL);
    pthread_mutex_init(&app.subserver_mutex, NULL);

    /* Dark theme preference */
    g_object_set(gtk_settings_get_default(),
        "gtk-application-prefer-dark-theme", TRUE, NULL);

    /* Initialize storage directories */
    storage_init();

    /* Scan for Tor circuits */
    tor_init_circuits();

    /* Handle signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Print startup info */
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════╗\n"
        "║  Veil-Xfer v" APP_VERSION
                  " — Encrypted Transfer  ║\n"
        "╠══════════════════════════════════════════╣\n"
        "║  AES-256-GCM  chunk encryption           ║\n"
        "║  RSA-4096     key wrapping               ║\n"
        "║  HKDF-SHA256  key derivation             ║\n"
        "║  PBKDF2-1M    password protection        ║\n"
        "║  Multi-Tor    circuit rotation           ║\n"
        "║  Distributed  chunk storage              ║\n"
        "║  Tor Onion    hidden service             ║\n"
        "║  Zero Trust   rate-limited access        ║\n"
        "╚══════════════════════════════════════════╝\n"
        "\n");

    int tc = tor_active_count();
    if (tc > 0)
        fprintf(stderr,
            "[+] %d Tor circuit(s) detected\n", tc);
    else
        fprintf(stderr,
            "[-] No Tor SOCKS circuits — "
            "direct mode for outgoing\n");

    /* Check if Tor binary is available for onion service */
    if (access("/usr/bin/tor", X_OK) == 0 ||
        access("/usr/sbin/tor", X_OK) == 0 ||
        access("/usr/local/bin/tor", X_OK) == 0)
        fprintf(stderr,
            "[+] Tor binary found — "
            "onion service available\n");
    else
        fprintf(stderr,
            "[-] Tor binary not found — "
            "install: sudo apt install tor\n");

    fprintf(stderr,
        "[*] Main server port: %d\n"
        "[*] Sub-server range: %d–%d (%d max)\n",
        SERVER_PORT,
        SUB_PORT_BASE, SUB_PORT_MAX, MAX_SUB_SERVERS);

    /* Load persistent advanced config */
    adv_config_load();

    /* Build and show GUI */
    gui_build();

    /* Enter GTK main loop */
    gtk_main();

    /* ══════════════════════════════════════════════════════════
     * CLEANUP — Order matters!
     * ══════════════════════════════════════════════════════════ */
    fprintf(stderr, "[Veil-Xfer] Cleaning up...\n");

    /* 0. Stop P2P sender (kills P2P Tor processes + sub-servers) */
    if (p2p_is_running())
        p2p_stop_sender(LOG_P2P);

    /* 1. Stop onion service (kills Tor child process) */
    onion_stop(LOG_SERVER);

    /* 2. Stop all sub-server HTTP daemons */
    storage_stop_subservers();

    /* 3. Free heap-allocated sub-server array  ← THIS WAS MISSING */
    if (app.sub_servers) {
        free(app.sub_servers);
        app.sub_servers = NULL;
        app.num_sub_servers = 0;
        app.sub_servers_cap = 0;
    }

    /* 4. Destroy mutexes */
    pthread_mutex_destroy(&app.file_mutex);
    pthread_mutex_destroy(&app.circuit_mutex);
    pthread_mutex_destroy(&app.stored_mutex);
    pthread_mutex_destroy(&app.subserver_mutex);

    tor_pool_stop(LOG_SERVER);
    /* 5. Cleanup curl */
    curl_global_cleanup();

    fprintf(stderr, "[Veil-Xfer] Goodbye.\n");
    return 0;
}