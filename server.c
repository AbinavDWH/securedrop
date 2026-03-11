#include "server.h"
#include "protocol.h"
#include "storage.h"
#include "network.h"
#include "gui_helpers.h"
#include "util.h"
#include "crypto.h"
#include "onion.h"
#include "parallel.h"
#include "sub_tor.h"

#include <openssl/crypto.h>

#define DEFAULT_SUB_COUNT  8

typedef struct { Buf buf; } ServerConn;
typedef struct { char address[256]; } OnionAddrUpdate;

static gboolean update_onion_label(gpointer data)
{
    OnionAddrUpdate *u = data;
    if (app.server_onion_label) {
        gtk_label_set_text(
            GTK_LABEL(app.server_onion_label),
            u->address);
        gtk_label_set_selectable(
            GTK_LABEL(app.server_onion_label),
            TRUE);
    }
    if (app.server_onion_status)
        gtk_label_set_markup(
            GTK_LABEL(app.server_onion_status),
            "<span color='#66bb6a'>"
            "\xE2\x9C\x93 Connected</span>");
    free(u);
    return G_SOURCE_REMOVE;
}

static void *onion_setup_thread(void *arg)
{
    int lt = *(int *)arg;
    free(arg);

    int rc = onion_wait_for_address(
        ONION_TIMEOUT_SEC, lt);

    if (rc == 0) {
        const char *addr =
            onion_get_full_address();
        if (addr) {
            gui_post_log(lt,
                "══════════════════════════"
                "═══════════");
            gui_post_log(lt,
                "\xF0\x9F\x8C\x8D MAIN "
                "ONION: %s", addr);
            gui_post_log(lt,
                "══════════════════════════"
                "═══════════");

            char display[512];
            snprintf(display, sizeof(display),
                "%s (main)", addr);
            gui_post_address(lt, display);

            OnionAddrUpdate *u =
                malloc(sizeof(*u));
            strncpy(u->address, addr,
                sizeof(u->address) - 1);
            u->address[
                sizeof(u->address) - 1] = 0;
            g_idle_add(update_onion_label, u);
        }
    }

    gui_post_log(lt,
        "Starting independent Tor per "
        "sub-server (1-2 minutes)...");

    int ready = sub_tor_start_all(lt);

    if (ready > 0) {
        gui_post_log(lt,
            "\xE2\x9C\x93 %d sub-servers have "
            "independent .onion addresses",
            ready);
    } else {
        gui_post_log(lt,
            "Sub-server Tor failed — "
            "single-connection mode only");
    }

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   DETECT IF REQUEST CAME VIA .ONION
   
   If the client connected through Tor to our
   .onion address, we can only return sub-server
   entries that are ALSO reachable via Tor
   (i.e. have their own .onion address).
   
   We can't return 127.0.0.1:10005 because the
   client is remote — they can't reach our
   localhost.
   
   We can't return main.onion:10005 because
   the main Tor only forwards port 80.
   ──────────────────────────────────────────────────────────── */

static int request_is_remote(
    struct MHD_Connection *conn)
{
    /*
     * If the connection comes from 127.0.0.1,
     * it's either:
     *   - A LAN client connecting directly
     *   - Tor forwarding a .onion request
     *
     * We can't easily distinguish these, so
     * we check: does main Tor exist?
     * If yes, assume some clients are remote.
     *
     * Better approach: check the Host header
     * for .onion suffix.
     */
    const char *host = MHD_lookup_connection_value(
        conn, MHD_HEADER_KIND, "Host");

    if (host && strstr(host, ".onion"))
        return 1;

    return 0;
}

/* ────────────────────────────────────────────────────────────
   MAIN HTTP HANDLER
   ──────────────────────────────────────────────────────────── */

static enum MHD_Result main_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version, const char *upload_data,
    size_t *upload_data_size, void **con_cls)
{
    (void)cls; (void)version;

    /* GET /ping */
    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/ping") == 0) {

        const char *pong = "pong";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                4, (void *)pong,
                MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r,
            "Content-Type", "text/plain");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* POST /upload */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/upload") == 0) {

        if (!*con_cls) {
            ServerConn *sc =
                calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }
        ServerConn *sc = *con_cls;
        if (*upload_data_size > 0) {
            buf_add(&sc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char sz[64];
        human_size(sc->buf.len, sz, sizeof(sz));
        gui_post_log(LOG_SERVER,
            "Upload received: %s", sz);

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        int rc = protocol_parse_upload(
            sc->buf.data, sc->buf.len,
            file_id, LOG_SERVER);

        char resp_buf[256];
        const char *resp;
        int status;

        if (rc == 0) {
            snprintf(resp_buf, sizeof(resp_buf),
                "{\"status\":\"ok\","
                "\"file_id\":\"%s\"}\n",
                file_id);
            resp = resp_buf;
            status = 200;
            app.upload_count++;
            gui_post_uploads(app.upload_count);
        } else {
            resp = "{\"status\":\"error\"}\n";
            status = 500;
        }

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(resp), (void *)resp,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/json");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                (unsigned)status, r);
        MHD_destroy_response(r);
        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    /* POST /download */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/download") == 0) {

        if (!*con_cls) {
            ServerConn *sc =
                calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }
        ServerConn *sc = *con_cls;
        if (*upload_data_size > 0) {
            buf_add(&sc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        char password[256] = {0};

        if (sc->buf.len >
            FILE_ID_HEX_LEN + 1) {
            memcpy(file_id, sc->buf.data,
                   FILE_ID_HEX_LEN);
            size_t poff = FILE_ID_HEX_LEN + 1;
            size_t plen = sc->buf.len - poff;
            if (plen > sizeof(password) - 1)
                plen = sizeof(password) - 1;
            memcpy(password,
                   sc->buf.data + poff, plen);
        } else {
            const char *e =
                "{\"error\":\"bad\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 400, r);
            MHD_destroy_response(r);
            buf_free(&sc->buf);
            free(sc);
            *con_cls = NULL;
            return rv;
        }

        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;

        Buf response;
        buf_init(&response);
        int rc = protocol_build_download(
            file_id, password, &response,
            LOG_SERVER);
        secure_wipe(password, sizeof(password));

        if (rc == 0) {
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    response.len, response.data,
                    MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r,
                "Content-Type",
                "application/octet-stream");
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 200, r);
            MHD_destroy_response(r);
            buf_free(&response);
            app.download_count++;
            gui_post_downloads(
                app.download_count);
            return rv;
        }
        buf_free(&response);
        const char *e =
            "{\"error\":\"denied\"}\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(e), (void *)e,
                MHD_RESPMEM_PERSISTENT);
        return MHD_queue_response(
            conn, 403, r);
    }

    /* GET /list */
    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/list") == 0) {

        Buf json;
        buf_init(&json);
        buf_add(&json, "[", 1);

        pthread_mutex_lock(&app.stored_mutex);
        for (int i = 0;
             i < app.stored_file_count; i++) {
            StoredFileMeta *m =
                &app.stored_files[i];
            char entry[1024], sz[64];
            human_size(m->original_size,
                       sz, sizeof(sz));
            snprintf(entry, sizeof(entry),
                "%s{\"id\":\"%.16s...\","
                "\"name\":\"%s\","
                "\"size\":\"%s\","
                "\"chunks\":%u}",
                i > 0 ? "," : "",
                m->file_id, m->original_name,
                sz, m->chunk_count);
            buf_add(&json, entry, strlen(entry));
        }
        pthread_mutex_unlock(&app.stored_mutex);

        buf_add(&json, "]\n", 2);
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                json.len, json.data,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/json");
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        buf_free(&json);
        return rv;
    }

    /* GET / or /status */
    if (strcmp(method, "GET") == 0 &&
        (strcmp(url, "/") == 0 ||
         strcmp(url, "/status") == 0)) {

        const char *onion =
            onion_get_full_address();
        int subs = 0, tor_subs = 0;
        pthread_mutex_lock(&app.subserver_mutex);
        for (int i = 0;
             i < app.num_sub_servers; i++) {
            if (app.sub_servers[i].active)
                subs++;
            if (app.sub_servers[i].tor_ready)
                tor_subs++;
        }
        pthread_mutex_unlock(
            &app.subserver_mutex);

        char page[8192];
        snprintf(page, sizeof(page),
            "<html><body style=\"background:"
            "#0a0a1a;color:#c0c0d0;"
            "font-family:monospace;"
            "padding:40px;\">"
            "<h1 style=\"color:#4fc3f7;\">"
            "SecureDrop v%s</h1>"
            "<p>Files: %d | Up: %d | "
            "Down: %d</p>"
            "<p>Sub-servers: %d active, "
            "%d with independent .onion</p>"
            "%s%s%s"
            "</body></html>",
            APP_VERSION,
            app.stored_file_count,
            app.upload_count,
            app.download_count,
            subs, tor_subs,
            onion ? "<p>Main: " : "",
            onion ? onion : "",
            onion ? "</p>" : "");

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(page), (void *)page,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type", "text/html");
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* ════════════════════════════════════════════
       GET /servers — sub-server list

       CRITICAL RULE:
       Only return addresses the client can
       actually reach.

       For .onion clients:
         - ONLY sub-servers with their own
           independent .onion address
         - NEVER main_onion:sub_port (main Tor
           only forwards port 80)
         - NEVER 127.0.0.1:port (client is remote)

       For LAN clients:
         - 127.0.0.1:port or LAN_IP:port
       ════════════════════════════════════════════ */

    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/servers") == 0) {

        int remote = request_is_remote(conn);

        Buf list;
        buf_init(&list);

        char lan_ip[256];
        get_primary_ip(lan_ip, sizeof(lan_ip));

        int listed = 0;

        pthread_mutex_lock(&app.subserver_mutex);
        for (int i = 0;
             i < app.num_sub_servers; i++) {
            SubServer *ss =
                &app.sub_servers[i];
            if (!ss->active) continue;

            char line[512];

            if (remote) {
                /*
                 * Client connected via .onion
                 *
                 * ONLY include sub-servers that
                 * have their OWN independent
                 * .onion address with Tor ready.
                 *
                 * Each independent .onion maps
                 * virtual port 80 to the sub-
                 * server's local port.
                 *
                 * DO NOT fall back to
                 * main.onion:10005 — that port
                 * is NOT in main Tor's torrc.
                 */
                if (ss->tor_ready &&
                    ss->onion_addr[0]) {
                    snprintf(line, sizeof(line),
                        "%s:80\n",
                        ss->onion_addr);
                    buf_add(&list, line,
                            strlen(line));
                    listed++;
                }
                /* Skip sub-servers without
                   their own .onion — they are
                   simply unreachable from
                   remote clients */

            } else {
                /*
                 * LAN client — direct access
                 * to local ports
                 */
                snprintf(line, sizeof(line),
                    "%s:%d\n",
                    lan_ip, ss->port);
                buf_add(&list, line,
                        strlen(line));
                listed++;
            }
        }
        pthread_mutex_unlock(
            &app.subserver_mutex);

        if (listed == 0) {
            buf_free(&list);

            /* Tell client why */
            const char *reason;
            if (remote) {
                reason =
                    "{\"error\":"
                    "\"no sub-servers have "
                    "independent .onion "
                    "addresses yet — use "
                    "single-connection mode\"}\n";
            } else {
                reason =
                    "{\"error\":"
                    "\"no active "
                    "sub-servers\"}\n";
            }

            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(reason),
                    (void *)reason,
                    MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r,
                "Content-Type",
                "application/json");
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 503, r);
            MHD_destroy_response(r);
            return rv;
        }

        gui_post_log(LOG_SERVER,
            "/servers: returning %d "
            "sub-servers (%s client)",
            listed,
            remote ? "remote/.onion" : "LAN");

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                list.len, list.data,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type", "text/plain");
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        buf_free(&list);
        return rv;
    }

    /* POST /upload-parallel */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/upload-parallel") == 0) {

        if (!*con_cls) {
            ServerConn *sc =
                calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }
        ServerConn *sc = *con_cls;
        if (*upload_data_size > 0) {
            buf_add(&sc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        int rc = protocol_parse_upload_metadata(
            sc->buf.data, sc->buf.len,
            file_id, LOG_SERVER);

        char resp_buf[256];
        const char *resp;
        int status;

        if (rc == 0) {
            snprintf(resp_buf, sizeof(resp_buf),
                "{\"status\":\"ok\","
                "\"file_id\":\"%s\","
                "\"mode\":\"parallel\"}\n",
                file_id);
            resp = resp_buf;
            status = 200;
            app.upload_count++;
            gui_post_uploads(app.upload_count);
        } else {
            resp = "{\"status\":\"error\"}\n";
            status = 500;
        }

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(resp), (void *)resp,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/json");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                (unsigned)status, r);
        MHD_destroy_response(r);
        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    /* POST /download-parallel */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/download-parallel") == 0) {

        if (!*con_cls) {
            ServerConn *sc =
                calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }
        ServerConn *sc = *con_cls;
        if (*upload_data_size > 0) {
            buf_add(&sc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        char password[256] = {0};

        if (sc->buf.len >
            FILE_ID_HEX_LEN + 1) {
            memcpy(file_id, sc->buf.data,
                   FILE_ID_HEX_LEN);
            size_t poff = FILE_ID_HEX_LEN + 1;
            size_t plen = sc->buf.len - poff;
            if (plen > sizeof(password) - 1)
                plen = sizeof(password) - 1;
            memcpy(password,
                   sc->buf.data + poff, plen);
        } else {
            buf_free(&sc->buf);
            free(sc);
            *con_cls = NULL;
            const char *e =
                "{\"error\":\"bad\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            return MHD_queue_response(
                conn, 400, r);
        }

        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;

        Buf response;
        buf_init(&response);
        int rc =
            protocol_build_download_metadata(
                file_id, password, &response,
                LOG_SERVER);
        secure_wipe(password, sizeof(password));

        if (rc == 0) {
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    response.len, response.data,
                    MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r,
                "Content-Type",
                "application/octet-stream");
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 200, r);
            MHD_destroy_response(r);
            buf_free(&response);
            app.download_count++;
            gui_post_downloads(
                app.download_count);
            return rv;
        }

        buf_free(&response);
        const char *e =
            "{\"error\":\"denied\"}\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(e), (void *)e,
                MHD_RESPMEM_PERSISTENT);
        return MHD_queue_response(
            conn, 403, r);
    }

    /* 404 */
    const char *nf =
        "{\"error\":\"not found\"}\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf,
            MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn, 404, r);
}

/* ────────────────────────────────────────────────────────────
   SERVER START
   ──────────────────────────────────────────────────────────── */

void server_start(int log_target)
{
    if (app.server_running) {
        gui_post_log(log_target,
            "Already running");
        return;
    }

    storage_init();

    if (!file_exists(RSA_PUB_FILE) ||
        !file_exists(RSA_PRIV_FILE)) {
        gui_post_log(log_target,
            "Generating RSA-2048...");
        gen_rsa_keys_to_file(RSA_PUB_FILE,
                             RSA_PRIV_FILE);
    }

    storage_load_all_meta(log_target);

    if (app.num_sub_servers == 0) {
        gui_post_log(log_target,
            "Creating %d sub-servers...",
            DEFAULT_SUB_COUNT);
        storage_add_subservers_batch(
            DEFAULT_SUB_COUNT, log_target);
    } else {
        storage_start_all_subservers(log_target);
    }

    app.server_daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_ERROR_LOG,
        SERVER_PORT, NULL, NULL,
        &main_handler, NULL,
        MHD_OPTION_END);

    if (!app.server_daemon) {
        gui_post_log(log_target,
            "Cannot bind port %d", SERVER_PORT);
        return;
    }

    app.server_running = 1;
    app.download_count = 0;
    app.upload_count = 0;

    char addr_buf[4096];
    get_local_addresses(addr_buf,
        sizeof(addr_buf), SERVER_PORT);
    gui_post_log(log_target, "%s", addr_buf);

    char primary[256];
    get_primary_ip(primary, sizeof(primary));
    char display[512];
    snprintf(display, sizeof(display),
        "%s:%d (LAN)", primary, SERVER_PORT);
    gui_post_address(log_target, display);

    gui_post_log(log_target,
        "Server on port %d", SERVER_PORT);

    gui_post_log(log_target,
        "Starting main Tor hidden service...");

    int rc = onion_start(SERVER_PORT, log_target);

    if (rc == 0) {
        int *lt = malloc(sizeof(int));
        *lt = log_target;
        pthread_t t;
        pthread_create(&t, NULL,
                       onion_setup_thread, lt);
        pthread_detach(t);
    } else {
        gui_post_log(log_target,
            "Tor unavailable — LAN-only mode");
    }
}

/* ────────────────────────────────────────────────────────────
   SERVER STOP
   ──────────────────────────────────────────────────────────── */

void server_stop(int log_target)
{
    if (!app.server_running) return;

    sub_tor_stop_all(log_target);
    onion_stop(log_target);

    MHD_stop_daemon(app.server_daemon);
    app.server_daemon = NULL;
    app.server_running = 0;

    storage_stop_subservers();

    gui_post_log(log_target, "Server stopped");
    gui_post_address(log_target, "Offline");

    if (app.server_onion_label)
        gtk_label_set_text(
            GTK_LABEL(app.server_onion_label),
            "Not running");
    if (app.server_onion_status)
        gtk_label_set_markup(
            GTK_LABEL(app.server_onion_status),
            "<span color='#707090'>"
            "Offline</span>");
}