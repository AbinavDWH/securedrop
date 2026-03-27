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

/* ── Rate limiting (per-IP brute-force protection) ─────────── */

typedef struct {
    char     ip[64];
    int      fail_count;
    time_t   last_fail;
    time_t   lockout_until;
} RateEntry;

static RateEntry rate_table[MAX_RATE_ENTRIES];
static pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;

static int rate_limit_check(const char *ip)
{
    pthread_mutex_lock(&rate_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (rate_table[i].ip[0] &&
            strcmp(rate_table[i].ip, ip) == 0) {
            if (rate_table[i].lockout_until > now) {
                pthread_mutex_unlock(&rate_mutex);
                return -1; /* locked out */
            }
            if (rate_table[i].lockout_until &&
                rate_table[i].lockout_until <= now) {
                rate_table[i].fail_count = 0;
                rate_table[i].lockout_until = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&rate_mutex);
    return 0;
}

static void rate_limit_record_fail(const char *ip)
{
    pthread_mutex_lock(&rate_mutex);
    time_t now = time(NULL);
    int slot = -1;
    int oldest = 0;
    time_t oldest_time = now + 1;

    for (int i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (rate_table[i].ip[0] &&
            strcmp(rate_table[i].ip, ip) == 0) {
            slot = i;
            break;
        }
        if (!rate_table[i].ip[0] && slot < 0)
            slot = i;
        if (rate_table[i].last_fail < oldest_time) {
            oldest_time = rate_table[i].last_fail;
            oldest = i;
        }
    }
    if (slot < 0) slot = oldest;

    if (!rate_table[slot].ip[0] ||
        strcmp(rate_table[slot].ip, ip) != 0) {
        memset(&rate_table[slot], 0, sizeof(RateEntry));
        strncpy(rate_table[slot].ip, ip, sizeof(rate_table[slot].ip) - 1);
    }

    rate_table[slot].fail_count++;
    rate_table[slot].last_fail = now;

    if (rate_table[slot].fail_count >= RATE_LIMIT_MAX_FAILS)
        rate_table[slot].lockout_until = now + RATE_LIMIT_LOCKOUT_SEC;

    pthread_mutex_unlock(&rate_mutex);
}

static void rate_limit_clear(const char *ip)
{
    pthread_mutex_lock(&rate_mutex);
    for (int i = 0; i < MAX_RATE_ENTRIES; i++) {
        if (rate_table[i].ip[0] &&
            strcmp(rate_table[i].ip, ip) == 0) {
            memset(&rate_table[i], 0, sizeof(RateEntry));
            break;
        }
    }
    pthread_mutex_unlock(&rate_mutex);
}

/* ── Strict hex file ID validation ─────────────────────────── */

static int validate_file_id_hex(const char *fid)
{
    if (!fid) return -1;
    for (int i = 0; i < FILE_ID_HEX_LEN; i++) {
        char c = fid[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return -1;
    }
    if (fid[FILE_ID_HEX_LEN] != '\0')
        return -1;
    return 0;
}

/* ── Security headers helper ───────────────────────────────── */

static void add_security_headers(struct MHD_Response *r)
{
    MHD_add_response_header(r, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(r, "X-Frame-Options", "DENY");
    MHD_add_response_header(r, "Cache-Control", "no-store");
    MHD_add_response_header(r, "X-Robots-Tag", "noindex, nofollow");
}

/* ── Get client IP from connection ─────────────────────────── */

static const char *get_client_ip(
    struct MHD_Connection *conn,
    char *buf, size_t bufsz)
{
    const union MHD_ConnectionInfo *ci =
        MHD_get_connection_info(conn,
            MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci && ci->client_addr) {
        struct sockaddr *sa = ci->client_addr;
        if (sa->sa_family == AF_INET) {
            inet_ntop(AF_INET,
                &((struct sockaddr_in *)sa)->sin_addr,
                buf, (socklen_t)bufsz);
            return buf;
        } else if (sa->sa_family == AF_INET6) {
            inet_ntop(AF_INET6,
                &((struct sockaddr_in6 *)sa)->sin6_addr,
                buf, (socklen_t)bufsz);
            return buf;
        }
    }
    strncpy(buf, "unknown", bufsz - 1);
    buf[bufsz - 1] = '\0';
    return buf;
}

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
                "MAIN ONION: %s", addr);
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

    int ready = sub_tor_start_selected(app.user_tor_count, lt);

    if (ready > 0) {
        gui_post_log(lt,
            "%d sub-servers have "
            "independent .onion addresses",
            ready);
    } else {
        gui_post_log(lt,
            "Sub-server Tor failed — "
            "single-connection mode only");
    }

    return NULL;
}

static int request_is_remote(
    struct MHD_Connection *conn)
{
    const char *host = MHD_lookup_connection_value(
        conn, MHD_HEADER_KIND, "Host");

    if (host && strstr(host, ".onion"))
        return 1;

    return 0;
}

/* ────────────────────────────────────────────────────────────
   PARSE file_id + password FROM REQUEST BODY
   
   Wire format: [64 bytes file_id] \0 [password]
   
   Used by /download, /download-parallel
   ──────────────────────────────────────────────────────────── */

static int parse_download_request(
    const unsigned char *data, size_t len,
    char *file_id_out, char *password_out,
    size_t password_max)
{
    if (len <= FILE_ID_HEX_LEN + 1)
        return -1;

    memcpy(file_id_out, data, FILE_ID_HEX_LEN);
    file_id_out[FILE_ID_HEX_LEN] = '\0';

    /* Strict hex validation */
    if (validate_file_id_hex(file_id_out) != 0)
        return -1;

    size_t poff = FILE_ID_HEX_LEN + 1;
    size_t plen = len - poff;
    if (plen > password_max - 1)
        plen = password_max - 1;

    memcpy(password_out, data + poff, plen);
    password_out[plen] = '\0';

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

    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/ping") == 0) {

        const char *pong = "pong";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                4, (void *)pong, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "text/plain");
        add_security_headers(r);
        enum MHD_Result rv = MHD_queue_response(conn, MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/upload") == 0) {

        if (!*con_cls) {
            ServerConn *sc = calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }

        ServerConn *sc = *con_cls;

        if (*upload_data_size > 0) {
            if (sc->buf.len + *upload_data_size > (size_t)512 * 1024 * 1024) {
                buf_free(&sc->buf);
                free(sc);
                *con_cls = NULL;
                const char *e = "{\"error\":\"payload too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(r, "Content-Type", "application/json");
                enum MHD_Result rv = MHD_queue_response(conn, 413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&sc->buf, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char sz[64];
        human_size(sc->buf.len, sz, sizeof(sz));
        gui_post_log(LOG_SERVER, "Upload received: %s", sz);

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        int rc = protocol_parse_upload(
            sc->buf.data, sc->buf.len, file_id, LOG_SERVER);

        char resp_buf[256];
        const char *resp;
        int status;

        if (rc == 0) {
            snprintf(resp_buf, sizeof(resp_buf),
                "{\"status\":\"ok\",\"file_id\":\"%s\"}\n", file_id);
            resp = resp_buf;
            status = 200;
            gui_post_uploads(app.upload_count);
        } else {
            resp = "{\"status\":\"error\"}\n";
            status = 500;
        }

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(resp), (void *)resp, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r, "Content-Type", "application/json");
        enum MHD_Result rv = MHD_queue_response(conn, (unsigned)status, r);
        MHD_destroy_response(r);
        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/download") == 0) {

        if (!*con_cls) {
            ServerConn *sc = calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }

        ServerConn *sc = *con_cls;

        if (*upload_data_size > 0) {
            if (sc->buf.len + *upload_data_size > (size_t)1 * 1024 * 1024) {
                buf_free(&sc->buf);
                free(sc);
                *con_cls = NULL;
                const char *e = "{\"error\":\"payload too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(r, "Content-Type", "application/json");
                enum MHD_Result rv = MHD_queue_response(conn, 413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&sc->buf, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        char password[256] = {0};

        if (parse_download_request(
                sc->buf.data, sc->buf.len,
                file_id, password, sizeof(password)) != 0) {

            const char *e = "{\"error\":\"malformed request\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r, "Content-Type", "application/json");
            enum MHD_Result rv = MHD_queue_response(conn, 400, r);
            MHD_destroy_response(r);
            buf_free(&sc->buf);
            free(sc);
            *con_cls = NULL;
            return rv;
        }

        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;

        /* Rate limiting check */
        char client_ip[64];
        get_client_ip(conn, client_ip, sizeof(client_ip));
        if (rate_limit_check(client_ip) != 0) {
            gui_post_log(LOG_SERVER, "Rate limited: %s", client_ip);
            secure_wipe(password, sizeof(password));
            const char *e = "{\"error\":\"rate_limited\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r, "Content-Type", "application/json");
            add_security_headers(r);
            enum MHD_Result rv = MHD_queue_response(conn, 429, r);
            MHD_destroy_response(r);
            return rv;
        }

        gui_post_log(LOG_SERVER, "/download request for %.16s...", file_id);

        Buf response;
        buf_init(&response);
        int rc = protocol_build_download(
            file_id, password, &response, LOG_SERVER);
        secure_wipe(password, sizeof(password));

        if (rc == 0) {
            rate_limit_clear(client_ip);
            char sz[64];
            human_size(response.len, sz, sizeof(sz));
            gui_post_log(LOG_SERVER, "Sending %s to client", sz);

            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    response.len, response.data, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r, "Content-Type", "application/octet-stream");
            add_security_headers(r);
            enum MHD_Result rv = MHD_queue_response(conn, 200, r);
            MHD_destroy_response(r);
            buf_free(&response);
            pthread_mutex_lock(&app.stored_mutex);
            app.download_count++;
            pthread_mutex_unlock(&app.stored_mutex);
            gui_post_downloads(app.download_count);
            return rv;
        }

        buf_free(&response);

        gui_post_log(LOG_SERVER, "Download DENIED for %.16s...", file_id);
        rate_limit_record_fail(client_ip);

        const char *err = "{\"error\":\"access_denied\"}\n";

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(err), (void *)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        add_security_headers(r);
        enum MHD_Result rv = MHD_queue_response(conn, 403, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* /list endpoint REMOVED — zero trust: no file enumeration */

    if (strcmp(method, "GET") == 0 &&
        (strcmp(url, "/") == 0 || strcmp(url, "/status") == 0)) {

        /* Zero trust: no version, no internals */
        const char *status_json = "{\"status\":\"running\"}\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(status_json), (void *)status_json, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        add_security_headers(r);
        enum MHD_Result rv = MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        return rv;
    }

    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/servers") == 0) {

        int remote = request_is_remote(conn);
        Buf list;
        buf_init(&list);
        char lan_ip[256];
        get_primary_ip(lan_ip, sizeof(lan_ip));
        int listed = 0;

        pthread_mutex_lock(&app.subserver_mutex);
        for (int i = 0; i < app.num_sub_servers; i++) {
            SubServer *ss = &app.sub_servers[i];
            if (!ss->active) continue;
            char line[512];
            if (remote) {
                if (ss->tor_ready && ss->onion_addr[0]) {
                    snprintf(line, sizeof(line), "%s:80\n", ss->onion_addr);
                    buf_add(&list, line, strlen(line));
                    listed++;
                }
            } else {
                snprintf(line, sizeof(line), "%s:%d\n", lan_ip, ss->port);
                buf_add(&list, line, strlen(line));
                listed++;
            }
        }
        pthread_mutex_unlock(&app.subserver_mutex);

        if (listed == 0) {
            buf_free(&list);
            const char *reason = remote
                ? "{\"error\":\"no sub-servers have independent .onion addresses yet\"}\n"
                : "{\"error\":\"no active sub-servers\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(reason), (void *)reason, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r, "Content-Type", "application/json");
            enum MHD_Result rv = MHD_queue_response(conn, 503, r);
            MHD_destroy_response(r);
            return rv;
        }

        gui_post_log(LOG_SERVER, "/servers: %d sub-servers (%s)",
            listed, remote ? "remote" : "LAN");

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                list.len, list.data, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r, "Content-Type", "text/plain");
        enum MHD_Result rv = MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        buf_free(&list);
        return rv;
    }

    if (strcmp(method, "POST") == 0 &&
        strncmp(url, "/upload-parallel", 16) == 0) {

        if (!*con_cls) {
            ServerConn *sc = calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }

        ServerConn *sc = *con_cls;

        if (*upload_data_size > 0) {
            if (sc->buf.len + *upload_data_size > (size_t)512 * 1024 * 1024) {
                buf_free(&sc->buf);
                free(sc);
                *con_cls = NULL;
                const char *e = "{\"error\":\"payload too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(r, "Content-Type", "application/json");
                enum MHD_Result rv = MHD_queue_response(conn, 413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&sc->buf, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char external_fid[FILE_ID_HEX_LEN + 1] = {0};

        if (strlen(url) > 17 && url[16] == '/') {
            const char *fid_str = url + 17;
            size_t fid_len = strlen(fid_str);
            if (fid_len > 0 && fid_str[fid_len - 1] == '/')
                fid_len--;
            if (fid_len == FILE_ID_HEX_LEN) {
                int valid_hex = 1;
                for (size_t vi = 0; vi < fid_len; vi++) {
                    char ch = fid_str[vi];
                    if (!((ch >= '0' && ch <= '9') ||
                          (ch >= 'a' && ch <= 'f') ||
                          (ch >= 'A' && ch <= 'F'))) {
                        valid_hex = 0;
                        break;
                    }
                }
                if (valid_hex) {
                    memcpy(external_fid, fid_str, fid_len);
                    external_fid[fid_len] = '\0';
                    gui_post_log(LOG_SERVER,
                        "Parallel upload with client file_id: %.16s...",
                        external_fid);
                }
            }
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        int rc = protocol_parse_upload_metadata(
            sc->buf.data, sc->buf.len, file_id,
            external_fid[0] ? external_fid : NULL, LOG_SERVER);

        char resp_buf[512];
        const char *resp;
        int status;

        if (rc == 0) {
            snprintf(resp_buf, sizeof(resp_buf),
                "{\"status\":\"ok\",\"file_id\":\"%s\",\"mode\":\"parallel\"}\n",
                file_id);
            resp = resp_buf;
            status = 200;
            gui_post_uploads(app.upload_count);
            gui_post_log(LOG_SERVER,
                "\xE2\x9C\x93 Parallel metadata stored: %s", file_id);
        } else {
            snprintf(resp_buf, sizeof(resp_buf),
                "{\"status\":\"error\",\"detail\":\"metadata parse failed\"}\n");
            resp = resp_buf;
            status = 500;
            gui_post_log(LOG_SERVER, "Parallel metadata FAILED");
        }

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(resp), (void *)resp, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r, "Content-Type", "application/json");
        enum MHD_Result rv = MHD_queue_response(conn, (unsigned)status, r);
        MHD_destroy_response(r);
        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    if (strcmp(method, "POST") == 0 &&
        (strcmp(url, "/download-parallel") == 0 ||
         strcmp(url, "/download-meta") == 0)) {

        if (!*con_cls) {
            ServerConn *sc = calloc(1, sizeof(*sc));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }

        ServerConn *sc = *con_cls;

        if (*upload_data_size > 0) {
            if (sc->buf.len + *upload_data_size > (size_t)1 * 1024 * 1024) {
                buf_free(&sc->buf);
                free(sc);
                *con_cls = NULL;
                const char *e = "{\"error\":\"payload too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(r, "Content-Type", "application/json");
                enum MHD_Result rv = MHD_queue_response(conn, 413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&sc->buf, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char file_id[FILE_ID_HEX_LEN + 1] = {0};
        char password[256] = {0};

        if (parse_download_request(
                sc->buf.data, sc->buf.len,
                file_id, password, sizeof(password)) != 0) {
            buf_free(&sc->buf);
            free(sc);
            *con_cls = NULL;
            const char *e = "{\"error\":\"malformed request\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r, "Content-Type", "application/json");
            enum MHD_Result rv = MHD_queue_response(conn, 400, r);
            MHD_destroy_response(r);
            return rv;
        }

        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;

        /* Rate limiting check */
        char client_ip[64];
        get_client_ip(conn, client_ip, sizeof(client_ip));
        if (rate_limit_check(client_ip) != 0) {
            gui_post_log(LOG_SERVER, "Rate limited: %s", client_ip);
            secure_wipe(password, sizeof(password));
            const char *e = "{\"error\":\"rate_limited\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r, "Content-Type", "application/json");
            add_security_headers(r);
            enum MHD_Result rv = MHD_queue_response(conn, 429, r);
            MHD_destroy_response(r);
            return rv;
        }

        gui_post_log(LOG_SERVER,
            "/download-parallel for %.16s...", file_id);

        Buf response;
        buf_init(&response);
        int rc = protocol_build_download_metadata(
            file_id, password, &response, LOG_SERVER);
        secure_wipe(password, sizeof(password));

        if (rc == 0) {
            rate_limit_clear(client_ip);
            char sz[64];
            human_size(response.len, sz, sizeof(sz));
            gui_post_log(LOG_SERVER,
                "Sending metadata %s (parallel)", sz);

            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    response.len, response.data, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r, "Content-Type", "application/octet-stream");
            add_security_headers(r);
            enum MHD_Result rv = MHD_queue_response(conn, 200, r);
            MHD_destroy_response(r);
            buf_free(&response);
            pthread_mutex_lock(&app.stored_mutex);
            app.download_count++;
            pthread_mutex_unlock(&app.stored_mutex);
            gui_post_downloads(app.download_count);
            return rv;
        }

        buf_free(&response);

        rate_limit_record_fail(client_ip);

        const char *err = "{\"error\":\"access_denied\"}\n";

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(err), (void *)err, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r, "Content-Type", "application/json");
        add_security_headers(r);
        enum MHD_Result rv = MHD_queue_response(conn, 403, r);
        MHD_destroy_response(r);
        return rv;
    }

    const char *nf = "{\"error\":\"not found\"}\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(r, "Content-Type", "application/json");
    enum MHD_Result rv = MHD_queue_response(conn, 404, r);
    MHD_destroy_response(r);
    return rv;
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
            "Generating RSA-4096...");
        gen_rsa_keys_to_file(RSA_PUB_FILE,
                             RSA_PRIV_FILE);
    }

    storage_load_all_meta(log_target);

    storage_start_all_subservers(log_target);

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(SERVER_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    app.server_daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_THREAD_PER_CONNECTION |
        MHD_USE_ERROR_LOG,
        SERVER_PORT, NULL, NULL,
        &main_handler, NULL,
        MHD_OPTION_CONNECTION_LIMIT,
        (unsigned int)32,
        MHD_OPTION_CONNECTION_TIMEOUT,
        (unsigned int)300,
        MHD_OPTION_CONNECTION_MEMORY_LIMIT,
        (size_t)(512 * 1024 * 1024),
        MHD_OPTION_SOCK_ADDR,
        (struct sockaddr *)&bind_addr,
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
        "Server on port %d "
        "(multi-threaded)", SERVER_PORT);

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
            "Tor unavailable — LAN-only");
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