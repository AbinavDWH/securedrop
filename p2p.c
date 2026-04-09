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

#include "p2p.h"
#include "protocol.h"
#include "crypto.h"
#include "gui_helpers.h"
#include "util.h"
#include "network.h"
#include "tor_pool.h"
#include "parallel.h"
#include "advanced_config.h"

#include <curl/curl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>

/* ══════════════════════════════════════════════════════════════
 * P2P STATE
 * ══════════════════════════════════════════════════════════════ */

static P2PState p2p = {0};

/* ── Forward declarations ──────────────────────────────────── */

static int  p2p_find_tor(char *out, size_t sz);
static void p2p_clean_datadir(const char *ddir);
static void p2p_fix_permissions(const char *hsdir);

/* ══════════════════════════════════════════════════════════════
 * CURL HELPERS
 * ══════════════════════════════════════════════════════════════ */

typedef struct { Buf *buf; } P2PCurlCtx;

static size_t p2p_write_cb(void *data, size_t size,
                           size_t nmemb, void *userp)
{
    P2PCurlCtx *ctx = userp;
    if (size != 0 && nmemb > SIZE_MAX / size)
        return 0;
    size_t total = size * nmemb;
    if (ctx->buf->len + total > (size_t)512 * 1024 * 1024)
        return 0;
    buf_add(ctx->buf, data, total);
    return total;
}

/* ══════════════════════════════════════════════════════════════
 * TOR UTILITIES
 * ══════════════════════════════════════════════════════════════ */

static int p2p_find_tor(char *out, size_t sz)
{
    const char *paths[] = {
        "/usr/bin/tor", "/usr/sbin/tor",
        "/usr/local/bin/tor", "/snap/bin/tor",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0) {
            strncpy(out, paths[i], sz - 1);
            out[sz - 1] = '\0';
            return 0;
        }
    }
    return -1;
}

static void p2p_clean_datadir(const char *ddir)
{
    const char *stale[] = {
        "lock", "tor.log", "stdout.log", "state",
        "cached-certs", "cached-consensus",
        "cached-descriptors", "cached-descriptors.new",
        "cached-microdesc-consensus",
        "cached-microdescs", "cached-microdescs.new",
        "unverified-consensus",
        "unverified-microdesc-consensus",
        NULL
    };
    for (int i = 0; stale[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s",
                 ddir, stale[i]);
        unlink(path);
    }
}

static void p2p_fix_permissions(const char *hsdir)
{
    chmod(hsdir, 0700);
    DIR *d = opendir(hsdir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path),
                 "%s/%s", hsdir, e->d_name);
        chmod(path, 0600);
    }
    closedir(d);
}

/* ── Check if Tor log shows descriptor published ──────────── */

static int p2p_check_hs_published(const char *ddir)
{
    char log_path[512];
    snprintf(log_path, sizeof(log_path),
             "%s/tor.log", ddir);

    FILE *f = fopen(log_path, "r");
    if (!f) return 0;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line,
                "Uploaded rendezvous "
                "descriptor") ||
            strstr(line,
                "Successfully uploaded") ||
            strstr(line,
                "Descriptor uploaded") ||
            strstr(line,
                "hs_service_upload_desc")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int p2p_check_bootstrapped(const char *ddir)
{
    char log_path[512];
    snprintf(log_path, sizeof(log_path),
             "%s/tor.log", ddir);
    FILE *f = fopen(log_path, "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Bootstrapped 100%")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/* ══════════════════════════════════════════════════════════════
 * P2P CHUNK STORE PATHS
 * ══════════════════════════════════════════════════════════════ */

#define P2P_STORE_DIR  "p2p_chunks"

static int p2p_validate_fid(const char *fid)
{
    size_t len = strlen(fid);
    if (len == 0 || len > FILE_ID_HEX_LEN)
        return -1;
    for (size_t i = 0; i < len; i++) {
        char c = fid[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return -1;
    }
    return 0;
}

static void p2p_chunk_dir(char *buf, size_t sz,
                          const char *fid)
{
    snprintf(buf, sz, "%s/%.16s",
             P2P_STORE_DIR, fid);
}

static void p2p_chunk_path(char *buf, size_t sz,
                           const char *fid,
                           uint32_t idx)
{
    snprintf(buf, sz,
             "%s/%.16s/chunk_%06u.bin",
             P2P_STORE_DIR, fid, idx);
}

/* ══════════════════════════════════════════════════════════════
 * P2P SUB-SERVER HTTP HANDLER
 * ══════════════════════════════════════════════════════════════ */

typedef struct {
    FILE  *fp;
    size_t total;
    char   path[4096];
    int    error;
} P2PSubConn;

static enum MHD_Result p2p_sub_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
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
        MHD_add_response_header(r,
            "Connection", "keep-alive");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* GET /health or / */
    if (strcmp(method, "GET") == 0 &&
        (strcmp(url, "/health") == 0 ||
         strcmp(url, "/") == 0)) {
        const char *ok = "OK\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                3, (void *)ok,
                MHD_RESPMEM_PERSISTENT);
        enum MHD_Result rv =
            MHD_queue_response(conn,
                MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* POST /store/{fid}/{idx} — streaming */
    if (strcmp(method, "POST") == 0 &&
        strncmp(url, "/store/", 7) == 0) {

        if (!*con_cls) {
            char fid[128] = {0};
            uint32_t cidx = 0;

            if (sscanf(url,
                    "/store/%64[^/]/%u",
                    fid, &cidx) != 2 ||
                p2p_validate_fid(fid) != 0 ||
                cidx > 999999) {

                const char *e = "Bad URL\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e,
                        MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv =
                    MHD_queue_response(conn,
                        400, r);
                MHD_destroy_response(r);
                return rv;
            }

            char dir[4096];
            p2p_chunk_dir(dir,
                sizeof(dir), fid);
            mkdir_p(dir, 0700);

            P2PSubConn *sc =
                calloc(1, sizeof(*sc));
            p2p_chunk_path(sc->path,
                sizeof(sc->path),
                fid, cidx);
            sc->fp = fopen(sc->path, "wb");

            if (!sc->fp) {
                free(sc);
                const char *e =
                    "Cannot create\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e,
                        MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv =
                    MHD_queue_response(conn,
                        500, r);
                MHD_destroy_response(r);
                return rv;
            }
            *con_cls = sc;
            return MHD_YES;
        }

        P2PSubConn *sc = *con_cls;

        if (*upload_data_size > 0) {
            if (!sc->error && sc->fp) {
                if (sc->total +
                    *upload_data_size >
                    (size_t)(CHUNK_SIZE +
                             4096)) {
                    sc->error = 1;
                } else {
                    size_t w = fwrite(
                        upload_data, 1,
                        *upload_data_size,
                        sc->fp);
                    if (w !=
                        *upload_data_size)
                        sc->error = 1;
                    sc->total += w;
                }
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (sc->fp) {
            fflush(sc->fp);
            fclose(sc->fp);
            sc->fp = NULL;
        }

        enum MHD_Result rv;
        if (sc->error) {
            unlink(sc->path);
            const char *e = "Write error\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            rv = MHD_queue_response(conn,
                500, r);
            MHD_destroy_response(r);
        } else {
            const char *ok = "OK\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    3, (void *)ok,
                    MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r,
                "Connection", "keep-alive");
            rv = MHD_queue_response(conn,
                200, r);
            MHD_destroy_response(r);
        }
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    /* GET /retrieve/{fid}/{idx} — zero-copy */
    if (strcmp(method, "GET") == 0 &&
        strncmp(url, "/retrieve/", 10) == 0) {

        char fid[128];
        uint32_t cidx = 0;

        if (sscanf(url,
                "/retrieve/%64[^/]/%u",
                fid, &cidx) != 2 ||
            p2p_validate_fid(fid) != 0 ||
            cidx > 999999) {

            const char *e = "Bad URL\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    400, r);
            MHD_destroy_response(r);
            return rv;
        }

        char path[4096];
        p2p_chunk_path(path, sizeof(path),
                       fid, cidx);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            const char *nf = "Not found\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(nf), (void *)nf,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    404, r);
            MHD_destroy_response(r);
            return rv;
        }

        struct stat st;
        if (fstat(fd, &st) != 0 ||
            st.st_size <= 0) {
            close(fd);
            const char *e = "Empty\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    404, r);
            MHD_destroy_response(r);
            return rv;
        }

        struct MHD_Response *r =
            MHD_create_response_from_fd(
                (uint64_t)st.st_size, fd);
        MHD_add_response_header(r,
            "Content-Type",
            "application/octet-stream");
        MHD_add_response_header(r,
            "Connection", "keep-alive");
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* 404 */
    const char *nf = "Not Found\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf,
            MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn, 404, r);
}

/* ══════════════════════════════════════════════════════════════
 * ADD THIS HELPER FUNCTION before p2p_main_handler
 *
 * Converts the upload-format payload header into
 * download-format that protocol_parse_download expects.
 *
 * Upload format:  SD4U | ver | salt | verify | keys... | chunks
 * Download format: SD4D | ver | salt | verify | keys... | chunks
 *
 * The ONLY difference in the header is the magic bytes!
 * The rest (salt, verify, RSA keys, master key, filename,
 * filesize, chunk_count) is identical in both formats.
 *
 * For chunks: upload format stores them as:
 *   [4 chunk_idx] [4 ctlen] [12 iv] [16 tag] [ctlen ct]
 * Download format is IDENTICAL.
 *
 * So the fix is simply: copy the payload and change
 * the first 4 bytes from "SD4U" to "SD4D".
 * ══════════════════════════════════════════════════════════════ */

static int p2p_build_download_payload(
    const unsigned char *upload_payload,
    size_t upload_len,
    Buf *download_out)
{
    if (upload_len < 8)
        return -1;

    /* Verify it's an upload payload */
    if (memcmp(upload_payload,
               PROTO_MAGIC_UPLOAD, 4) != 0)
        return -1;

    /* Copy entire payload */
    buf_reserve(download_out, upload_len);
    buf_add(download_out,
            upload_payload, upload_len);

    /* Overwrite magic: SD4U → SD4D */
    memcpy(download_out->data,
           PROTO_MAGIC_DOWNLOAD, 4);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * P2P MAIN HTTP HANDLER
 *
 * Endpoints:
 *   GET  /p2p-ping          → status + file_id
 *   GET  /p2p-servers       → sub-server list
 *   POST /p2p-download      → metadata (parallel)
 *   POST /p2p-download-full → full payload (fallback)
 * ══════════════════════════════════════════════════════════════ */

typedef struct { Buf buf; } P2PMainConn;

static enum MHD_Result p2p_main_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    (void)cls; (void)version;

    /* ── GET /p2p-ping ─────────────────────── */
    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/p2p-ping") == 0) {

        char resp[2048];
        pthread_mutex_lock(&p2p.mutex);
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ready\","
            "\"filename\":\"%s\","
            "\"size\":%zu,"
            "\"chunks\":%u,"
            "\"subs\":%d,"
            "\"file_id\":\"%s\","
            "\"version\":2}\n",
            p2p.filename,
            p2p.filesize,
            p2p.chunk_count,
            p2p.num_subs,
            p2p.file_id);
        pthread_mutex_unlock(&p2p.mutex);

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(resp), (void *)resp,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/json");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* ── GET /p2p-servers ──────────────────── */
    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/p2p-servers") == 0) {

        const char *host =
            MHD_lookup_connection_value(
                conn, MHD_HEADER_KIND, "Host");
        int remote =
            (host && strstr(host, ".onion"));

        Buf list;
        buf_init(&list);
        int listed = 0;

        char lan_ip[256];
        get_primary_ip(lan_ip, sizeof(lan_ip));

        pthread_mutex_lock(&p2p.subs_mutex);
        for (int i = 0; i < p2p.num_subs;
             i++) {
            P2PSubServer *ss = &p2p.subs[i];
            if (!ss->active) continue;

            char line[512];
            if (remote) {
                if (ss->tor_ready &&
                    ss->onion_addr[0]) {
                    snprintf(line,
                        sizeof(line),
                        "%s:80\n",
                        ss->onion_addr);
                    buf_add(&list, line,
                            strlen(line));
                    listed++;
                }
            } else {
                snprintf(line,
                    sizeof(line),
                    "%s:%d\n",
                    lan_ip, ss->port);
                buf_add(&list, line,
                        strlen(line));
                listed++;
            }
        }
        pthread_mutex_unlock(&p2p.subs_mutex);

        if (listed == 0) {
            buf_free(&list);
            const char *e =
                "{\"error\":"
                "\"no sub-servers\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(r,
                "Content-Type",
                "application/json");
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    503, r);
            MHD_destroy_response(r);
            return rv;
        }

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

    /* ── POST /p2p-download (metadata) ─────── */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/p2p-download") == 0) {

        if (!*con_cls) {
            P2PMainConn *mc =
                calloc(1, sizeof(*mc));
            buf_init(&mc->buf);
            *con_cls = mc;
            return MHD_YES;
        }

        P2PMainConn *mc = *con_cls;

        if (*upload_data_size > 0) {
            if (mc->buf.len +
                *upload_data_size >
                (size_t)1024 * 1024) {
                buf_free(&mc->buf);
                free(mc);
                *con_cls = NULL;
                const char *e =
                    "{\"error\":"
                    "\"too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e,
                        MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv =
                    MHD_queue_response(conn,
                        413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&mc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char password[256] = {0};
        size_t pw_len = mc->buf.len;
        if (pw_len > sizeof(password) - 1)
            pw_len = sizeof(password) - 1;
        memcpy(password, mc->buf.data, pw_len);
        password[pw_len] = '\0';
        buf_free(&mc->buf);
        free(mc);
        *con_cls = NULL;

        unsigned char pwd_key[AES_KEY_LEN];

        pthread_mutex_lock(&p2p.mutex);

        if (password_derive_key(password,
                p2p.pw_salt, SALT_LEN,
                pwd_key, AES_KEY_LEN) != 0 ||
            password_check_verifier(pwd_key,
                p2p.pw_verify) != 0) {

            pthread_mutex_unlock(&p2p.mutex);
            secure_wipe(password,
                sizeof(password));
            secure_wipe(pwd_key,
                sizeof(pwd_key));

            gui_post_log(LOG_P2P,
                "P2P download denied: "
                "wrong password");

            const char *e =
                "{\"error\":"
                "\"wrong_password\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    403, r);
            MHD_destroy_response(r);
            return rv;
        }

        secure_wipe(password,
            sizeof(password));
        secure_wipe(pwd_key,
            sizeof(pwd_key));

        gui_post_log(LOG_P2P,
            "\xE2\x9C\x93 Password verified"
            " — sending metadata");

        /* FIX: Convert upload magic to
           download magic in metadata */
        Buf dl_meta;
        buf_init(&dl_meta);

        if (p2p_build_download_payload(
                p2p.payload,
                p2p.header_len,
                &dl_meta) != 0) {

            pthread_mutex_unlock(
                &p2p.mutex);
            buf_free(&dl_meta);

            const char *e =
                "{\"error\":"
                "\"conversion failed\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    500, r);
            MHD_destroy_response(r);
            return rv;
        }

        pthread_mutex_unlock(&p2p.mutex);

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                dl_meta.len,
                dl_meta.data,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/octet-stream");
        MHD_add_response_header(r,
            "X-Content-Type-Options",
            "nosniff");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                200, r);
        MHD_destroy_response(r);
        buf_free(&dl_meta);
        return rv;
    }

    /* ── POST /p2p-download-full (fallback) ── */
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/p2p-download-full") == 0) {

        if (!*con_cls) {
            P2PMainConn *mc =
                calloc(1, sizeof(*mc));
            buf_init(&mc->buf);
            *con_cls = mc;
            return MHD_YES;
        }

        P2PMainConn *mc = *con_cls;

        if (*upload_data_size > 0) {
            if (mc->buf.len +
                *upload_data_size >
                (size_t)1024 * 1024) {
                buf_free(&mc->buf);
                free(mc);
                *con_cls = NULL;
                const char *e =
                    "{\"error\":"
                    "\"too large\"}\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e,
                        MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv =
                    MHD_queue_response(conn,
                        413, r);
                MHD_destroy_response(r);
                return rv;
            }
            buf_add(&mc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char password[256] = {0};
        size_t pw_len = mc->buf.len;
        if (pw_len > sizeof(password) - 1)
            pw_len = sizeof(password) - 1;
        memcpy(password, mc->buf.data, pw_len);
        password[pw_len] = '\0';
        buf_free(&mc->buf);
        free(mc);
        *con_cls = NULL;

        unsigned char pwd_key[AES_KEY_LEN];

        pthread_mutex_lock(&p2p.mutex);

        if (password_derive_key(password,
                p2p.pw_salt, SALT_LEN,
                pwd_key, AES_KEY_LEN) != 0 ||
            password_check_verifier(pwd_key,
                p2p.pw_verify) != 0) {

            pthread_mutex_unlock(&p2p.mutex);
            secure_wipe(password,
                sizeof(password));
            secure_wipe(pwd_key,
                sizeof(pwd_key));

            const char *e =
                "{\"error\":"
                "\"wrong_password\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    403, r);
            MHD_destroy_response(r);
            return rv;
        }

        secure_wipe(password,
            sizeof(password));
        secure_wipe(pwd_key,
            sizeof(pwd_key));

        gui_post_log(LOG_P2P,
            "\xE2\x9C\x93 Sending full "
            "payload (single-conn)");

        /* FIX: Convert entire payload
           from upload to download format */
        Buf dl_full;
        buf_init(&dl_full);

        if (p2p_build_download_payload(
                p2p.payload,
                p2p.payload_len,
                &dl_full) != 0) {

            pthread_mutex_unlock(
                &p2p.mutex);
            buf_free(&dl_full);

            const char *e =
                "{\"error\":"
                "\"conversion failed\"}\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn,
                    500, r);
            MHD_destroy_response(r);
            return rv;
        }

        pthread_mutex_unlock(&p2p.mutex);

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                dl_full.len,
                dl_full.data,
                MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(r,
            "Content-Type",
            "application/octet-stream");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                200, r);
        MHD_destroy_response(r);
        buf_free(&dl_full);
        return rv;
    }

    /* 404 */
    const char *nf =
        "{\"error\":\"not found\"}\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf,
            MHD_RESPMEM_PERSISTENT);
    enum MHD_Result rv =
        MHD_queue_response(conn, 404, r);
    MHD_destroy_response(r);
    return rv;
}

/* ══════════════════════════════════════════════════════════════
 * START P2P SUB-SERVER (HTTP daemon)
 * ══════════════════════════════════════════════════════════════ */

static int p2p_start_sub(int index,
                         int log_target)
{
    pthread_mutex_lock(&p2p.subs_mutex);
    if (index < 0 ||
        index >= p2p.num_subs) {
        pthread_mutex_unlock(&p2p.subs_mutex);
        return -1;
    }

    P2PSubServer *ss = &p2p.subs[index];

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port =
        htons((uint16_t)ss->port);
    bind_addr.sin_addr.s_addr =
        htonl(INADDR_LOOPBACK);

    ss->daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_THREAD_PER_CONNECTION |
        MHD_USE_ERROR_LOG,
        (uint16_t)ss->port, NULL, NULL,
        &p2p_sub_handler, NULL,
        MHD_OPTION_CONNECTION_LIMIT,
        (unsigned int)32,
        MHD_OPTION_CONNECTION_TIMEOUT,
        (unsigned int)60,
        MHD_OPTION_SOCK_ADDR,
        (struct sockaddr *)&bind_addr,
        MHD_OPTION_END);

    if (!ss->daemon) {
        pthread_mutex_unlock(&p2p.subs_mutex);
        gui_post_log(log_target,
            "P2P sub[%d] failed port %d",
            index, ss->port);
        return -1;
    }

    ss->active = 1;
    pthread_mutex_unlock(&p2p.subs_mutex);

    if (index < 3 || index % 20 == 0)
        gui_post_log(log_target,
            "P2P sub[%d] on port %d",
            index, ss->port);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * START TOR FOR ONE P2P SUB-SERVER
 * ══════════════════════════════════════════════════════════════ */

static int p2p_start_sub_tor(int index,
                             int log_target)
{
    char tor_bin[512];
    if (p2p_find_tor(tor_bin,
            sizeof(tor_bin)) != 0)
        return -1;

    pthread_mutex_lock(&p2p.subs_mutex);
    if (index < 0 ||
        index >= p2p.num_subs ||
        !p2p.subs[index].active) {
        pthread_mutex_unlock(&p2p.subs_mutex);
        return -1;
    }
    int port = p2p.subs[index].port;
    pthread_mutex_unlock(&p2p.subs_mutex);

    char ddir[256];
    snprintf(ddir, sizeof(ddir),
             "tor_data/p2p_sub_%d", index);
    mkdir_p(ddir, 0700);

    char hsdir[300];
    snprintf(hsdir, sizeof(hsdir),
             "%s/hs", ddir);
    mkdir_p(hsdir, 0700);

    p2p_clean_datadir(ddir);
    p2p_fix_permissions(hsdir);

    char torrc[300];
    snprintf(torrc, sizeof(torrc),
             "%s/torrc", ddir);

    FILE *fp = fopen(torrc, "w");
    if (!fp) return -1;

    fprintf(fp,
        "SocksPort 0\n"
        "RunAsDaemon 0\n"
        "DataDirectory %s\n"
        "HiddenServiceDir %s\n"
        "HiddenServicePort 80 "
        "127.0.0.1:%d\n"
        "Log notice file %s/tor.log\n"
        "AvoidDiskWrites 1\n"
        "HiddenServiceMaxStreams 64\n"
        "HiddenServiceMaxStreamsCloseCircuit"
        " 0\n",
        ddir, hsdir, port, ddir);
    fclose(fp);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        char logp[300];
        snprintf(logp, sizeof(logp),
                 "%s/stdout.log", ddir);
        int fd = open(logp,
            O_WRONLY | O_CREAT | O_TRUNC,
            0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        int max_fd =
            (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 4096;
        for (int f = 3; f < max_fd; f++)
            close(f);
        execl(tor_bin, "tor",
              "-f", torrc, NULL);
        _exit(127);
    }

    pthread_mutex_lock(&p2p.subs_mutex);
    p2p.subs[index].tor_pid = pid;
    strncpy(p2p.subs[index].tor_datadir,
            ddir,
            sizeof(p2p.subs[index]
                       .tor_datadir) - 1);
    p2p.subs[index].tor_ready = 0;
    pthread_mutex_unlock(&p2p.subs_mutex);

    gui_post_log(log_target,
        "P2P sub[%d] Tor launched "
        "(PID %d, port %d)",
        index, pid, port);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * WAIT FOR P2P SUB TOR — 3-phase readiness
 *
 * Phase 0: hostname file appears
 * Phase 1: Bootstrapped 100%
 * Phase 2: HS descriptor uploaded (REACHABLE)
 *
 * FIX: Previous code returned as soon as
 *      hostname appeared. But the onion is NOT
 *      reachable until descriptor is published
 *      to directory servers. This caused the
 *      receiver's ping to timeout.
 * ══════════════════════════════════════════════════════════════ */

static int p2p_wait_sub_tor(int index,
                            int timeout_sec,
                            int log_target)
{
    pthread_mutex_lock(&p2p.subs_mutex);
    if (index < 0 ||
        index >= p2p.num_subs) {
        pthread_mutex_unlock(&p2p.subs_mutex);
        return -1;
    }

    char ddir[256];
    strncpy(ddir,
            p2p.subs[index].tor_datadir,
            sizeof(ddir) - 1);
    ddir[sizeof(ddir) - 1] = '\0';
    pid_t pid = p2p.subs[index].tor_pid;
    pthread_mutex_unlock(&p2p.subs_mutex);

    char hostname_path[400];
    snprintf(hostname_path,
             sizeof(hostname_path),
             "%s/hs/hostname", ddir);

    time_t start = time(NULL);
    int phase = 0;
    char onion_buf[256] = {0};

    while (time(NULL) - start < timeout_sec) {
        /* Check process alive */
        if (pid > 0) {
            int status;
            pid_t r = waitpid(pid, &status,
                              WNOHANG);
            if (r > 0) {
                gui_post_log(log_target,
                    "P2P sub[%d] Tor died",
                    index);
                return -1;
            }
        }

        /* Phase 0: hostname file */
        if (phase == 0) {
            FILE *fp = fopen(
                hostname_path, "r");
            if (fp) {
                if (fgets(onion_buf,
                    sizeof(onion_buf), fp)) {

                    size_t len =
                        strlen(onion_buf);
                    while (len > 0 &&
                        (onion_buf[len - 1]
                             == '\n' ||
                         onion_buf[len - 1]
                             == '\r' ||
                         onion_buf[len - 1]
                             == ' '))
                        onion_buf[--len] =
                            '\0';

                    if (len > 6 &&
                        strstr(onion_buf,
                               ".onion")) {
                        phase = 1;
                    }
                }
                fclose(fp);
            }
        }

        /* Phase 1: bootstrap complete */
        if (phase == 1) {
            if (p2p_check_bootstrapped(ddir))
                phase = 2;
        }

        /* Phase 2: HS descriptor published
           THIS IS THE KEY FIX — only mark
           ready after descriptor is uploaded
           to directory servers */
        if (phase == 2) {
            if (p2p_check_hs_published(ddir)) {
                gui_post_log(log_target,
                    "\xE2\x9C\x93 P2P sub[%d]"
                    " PUBLISHED: %.20s...",
                    index, onion_buf);

                pthread_mutex_lock(
                    &p2p.subs_mutex);
                strncpy(
                    p2p.subs[index].onion_addr,
                    onion_buf,
                    sizeof(p2p.subs[index]
                               .onion_addr)
                    - 1);
                p2p.subs[index].tor_ready = 1;
                pthread_mutex_unlock(
                    &p2p.subs_mutex);

                return 0;
            }
        }

        int elapsed =
            (int)(time(NULL) - start);
        if (elapsed > 0 &&
            elapsed % 30 == 0 && phase < 2)
            gui_post_log(log_target,
                "  P2P sub[%d] phase %d "
                "(%ds/%ds)",
                index, phase,
                elapsed, timeout_sec);

        usleep(500000);
    }

    /* Timeout fallback — use if we have
       hostname even if not confirmed */
    if (phase >= 1 && onion_buf[0] != '\0') {
        gui_post_log(log_target,
            "\xE2\x9A\xA0 P2P sub[%d] "
            "timeout but hostname ready",
            index);

        pthread_mutex_lock(&p2p.subs_mutex);
        strncpy(
            p2p.subs[index].onion_addr,
            onion_buf,
            sizeof(p2p.subs[index]
                       .onion_addr) - 1);
        p2p.subs[index].tor_ready = 1;
        pthread_mutex_unlock(
            &p2p.subs_mutex);
        return 0;
    }

    gui_post_log(log_target,
        "P2P sub[%d] Tor timeout "
        "(phase %d)", index, phase);
    return -1;
}

/* ══════════════════════════════════════════════════════════════
 * MAIN TOR FOR P2P — with 3-phase wait
 * ══════════════════════════════════════════════════════════════ */

static int p2p_start_main_tor(int port,
                              int log_target)
{
    char tor_bin[512];
    if (p2p_find_tor(tor_bin,
            sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor not found — LAN-only P2P");
        return -1;
    }

    char ddir[256];
    snprintf(ddir, sizeof(ddir),
             "tor_data/p2p_main");
    mkdir_p(ddir, 0700);

    char hsdir[300];
    snprintf(hsdir, sizeof(hsdir),
             "%s/hs", ddir);
    mkdir_p(hsdir, 0700);

    p2p_clean_datadir(ddir);
    p2p_fix_permissions(hsdir);

    char torrc[300];
    snprintf(torrc, sizeof(torrc),
             "%s/torrc", ddir);

    FILE *fp = fopen(torrc, "w");
    if (!fp) return -1;

    fprintf(fp,
        "SocksPort 0\n"
        "RunAsDaemon 0\n"
        "DataDirectory %s\n"
        "HiddenServiceDir %s\n"
        "HiddenServicePort 80 "
        "127.0.0.1:%d\n"
        "Log notice file %s/tor.log\n"
        "AvoidDiskWrites 1\n",
        ddir, hsdir, port, ddir);
    fclose(fp);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        char logp[300];
        snprintf(logp, sizeof(logp),
                 "%s/stdout.log", ddir);
        int fd = open(logp,
            O_WRONLY | O_CREAT | O_TRUNC,
            0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        int max_fd =
            (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 4096;
        for (int f = 3; f < max_fd; f++)
            close(f);
        execl(tor_bin, "tor",
              "-f", torrc, NULL);
        _exit(127);
    }

    p2p.main_tor_pid = pid;
    strncpy(p2p.main_tordata, ddir,
            sizeof(p2p.main_tordata) - 1);
    p2p.main_tor_ready = 0;

    gui_post_log(log_target,
        "P2P main Tor launched (PID %d)",
        pid);
    return 0;
}

/* ── Wait for main Tor — 3-phase ──────────────────────────── */

static int p2p_wait_main_tor(int timeout_sec,
                             int log_target)
{
    char hostname_path[400];
    snprintf(hostname_path,
             sizeof(hostname_path),
             "%s/hs/hostname",
             p2p.main_tordata);

    time_t start = time(NULL);
    int phase = 0;
    char onion_buf[256] = {0};

    while (time(NULL) - start < timeout_sec) {
        if (p2p.main_tor_pid > 0) {
            int status;
            pid_t r = waitpid(
                p2p.main_tor_pid,
                &status, WNOHANG);
            if (r > 0) {
                gui_post_log(log_target,
                    "P2P main Tor exited");
                return -1;
            }
        }

        if (phase == 0) {
            FILE *fp = fopen(
                hostname_path, "r");
            if (fp) {
                char addr[256];
                if (fgets(addr,
                    sizeof(addr), fp)) {

                    size_t len =
                        strlen(addr);
                    while (len > 0 &&
                        (addr[len - 1] ==
                             '\n' ||
                         addr[len - 1] ==
                             '\r'))
                        addr[--len] = '\0';

                    if (len > 6 &&
                        strstr(addr,
                               ".onion")) {
                        strncpy(onion_buf,
                            addr,
                            sizeof(
                                onion_buf)
                            - 1);
                        phase = 1;
                        gui_post_log(
                            log_target,
                            "  Main hostname"
                            " created");
                    }
                }
                fclose(fp);
            }
        }

        if (phase == 1) {
            if (p2p_check_bootstrapped(
                    p2p.main_tordata))
                phase = 2;
        }

        /* FIX: Wait for descriptor upload
           before declaring ready */
        if (phase == 2) {
            if (p2p_check_hs_published(
                    p2p.main_tordata)) {

                snprintf(p2p.main_onion,
                    sizeof(p2p.main_onion),
                    "%s:80", onion_buf);
                p2p.main_tor_ready = 1;

                gui_post_log(log_target,
                    "\xE2\x9C\x93 P2P main "
                    "PUBLISHED: %s",
                    p2p.main_onion);
                return 0;
            }
        }

        int elapsed =
            (int)(time(NULL) - start);
        if (elapsed > 0 &&
            elapsed % 15 == 0)
            gui_post_log(log_target,
                "  P2P main Tor: phase %d "
                "(%ds/%ds)",
                phase, elapsed,
                timeout_sec);

        usleep(500000);
    }

    /* Timeout fallback */
    if (phase >= 1 && onion_buf[0] != '\0') {
        snprintf(p2p.main_onion,
            sizeof(p2p.main_onion),
            "%s:80", onion_buf);
        p2p.main_tor_ready = 1;
        gui_post_log(log_target,
            "\xE2\x9A\xA0 Main Tor timeout "
            "but hostname ready: %s",
            p2p.main_onion);
        return 0;
    }

    gui_post_log(log_target,
        "P2P main Tor timeout (phase %d)",
        phase);
    return -1;
}

/* ══════════════════════════════════════════════════════════════
 * DISTRIBUTE CHUNKS TO LOCAL SUB-SERVERS
 * ══════════════════════════════════════════════════════════════ */

static int p2p_distribute_chunks(
    int log_target)
{
    pthread_mutex_lock(&p2p.mutex);

    if (!p2p.payload ||
        p2p.chunk_count == 0) {
        pthread_mutex_unlock(&p2p.mutex);
        return -1;
    }

    uint32_t cc = p2p.chunk_count;
    int num_subs = p2p.num_subs;

    if (num_subs <= 0) {
        pthread_mutex_unlock(&p2p.mutex);
        return -1;
    }

    int cps = adv_config.chunks_per_sub;
    if (cps < 1) cps = 1;
    if (cps > 8) cps = 8;

    gui_post_log(log_target,
        "Distributing %u chunks across "
        "%d sub-servers "
        "(%d chunk(s)/sub)...",
        cc, num_subs, cps);

    int failed = 0;

    for (uint32_t i = 0; i < cc; i++) {
        int si = (int)((i / (uint32_t)cps) %
            (uint32_t)num_subs);

        const uint8_t *chunk_data =
            p2p.payload +
            p2p.chunk_offsets[i];
        uint32_t chunk_size =
            p2p.chunk_sizes[i];

        pthread_mutex_lock(
            &p2p.subs_mutex);
        int port = p2p.subs[si].port;
        int active = p2p.subs[si].active;
        pthread_mutex_unlock(
            &p2p.subs_mutex);

        if (!active) {
            /* Local fallback */
            char dir[4096];
            p2p_chunk_dir(dir,
                sizeof(dir), p2p.file_id);
            mkdir_p(dir, 0700);

            char path[4096];
            p2p_chunk_path(path,
                sizeof(path),
                p2p.file_id, i);
            FILE *fp = fopen(path, "wb");
            if (fp) {
                fwrite(chunk_data, 1,
                       chunk_size, fp);
                fclose(fp);
            } else {
                failed++;
            }
            continue;
        }

        char url[512];
        snprintf(url, sizeof(url),
            "http://127.0.0.1:%d"
            "/store/%s/%u",
            port, p2p.file_id, i);

        CURL *c = curl_easy_init();
        if (!c) { failed++; continue; }

        struct curl_slist *hdr = NULL;
        hdr = curl_slist_append(hdr,
            "Content-Type: "
            "application/octet-stream");

        curl_easy_setopt(c,
            CURLOPT_URL, url);
        curl_easy_setopt(c,
            CURLOPT_POST, 1L);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDS,
            chunk_data);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)chunk_size);
        curl_easy_setopt(c,
            CURLOPT_HTTPHEADER, hdr);
        curl_easy_setopt(c,
            CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(c,
            CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(c,
            CURLOPT_WRITEFUNCTION,
            p2p_write_cb);
        Buf discard;
        buf_init(&discard);
        P2PCurlCtx dctx = {
            .buf = &discard
        };
        curl_easy_setopt(c,
            CURLOPT_WRITEDATA, &dctx);

        CURLcode res =
            curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c,
            CURLINFO_RESPONSE_CODE,
            &code);

        curl_slist_free_all(hdr);
        curl_easy_cleanup(c);
        buf_free(&discard);

        if (res != CURLE_OK ||
            code != 200)
            failed++;

        if (i == 0 ||
            (i + 1) % 50 == 0 ||
            i + 1 == cc)
            gui_post_log(log_target,
                "  Distributed %u/%u "
                "chunks", i + 1, cc);

        gui_post_progress(log_target,
            0.3 + 0.3 *
            (double)(i + 1) / cc);
    }

    pthread_mutex_unlock(&p2p.mutex);

    if (failed > 0)
        gui_post_log(log_target,
            "WARNING: %d chunks failed",
            failed);
    else
        gui_post_log(log_target,
            "\xE2\x9C\x93 All %u chunks "
            "distributed", cc);

    return (failed > 0) ? -1 : 0;
}

/* ══════════════════════════════════════════════════════════════
 * PARSE PAYLOAD HEADER — chunk map
 * ══════════════════════════════════════════════════════════════ */

static int p2p_parse_chunk_map(int log_target)
{
    const uint8_t *d = p2p.payload;
    size_t rem = p2p.payload_len;
    int ok = 1;
    uint32_t tmp = 0;

    #define SKIP(n) do { \
        if (!ok) break; \
        if (rem < (size_t)(n)) ok = 0; \
        else { d += (n); rem -= (n); } \
    } while(0)

    #define READ32(var) do { \
        if (!ok) break; \
        if (rem < 4) ok = 0; \
        else { (var) = rd32(d); \
               d += 4; rem -= 4; } \
    } while(0)

    SKIP(4);             /* magic */
    SKIP(4);             /* version */
    SKIP(SALT_LEN);
    SKIP(HASH_LEN);
    READ32(tmp); SKIP(tmp);  /* rsa pub */
    SKIP(AES_IV_LEN);
    SKIP(AES_TAG_LEN);
    READ32(tmp); SKIP(tmp);  /* enc priv */
    READ32(tmp); SKIP(tmp);  /* enc master */
    READ32(tmp); SKIP(tmp);  /* filename */
    SKIP(8);                 /* filesize */

    uint32_t chunk_count = 0;
    READ32(chunk_count);

    #undef SKIP
    #undef READ32

    if (!ok || chunk_count == 0 ||
        chunk_count > MAX_CHUNKS) {
        gui_post_log(log_target,
            "P2P header parse failed");
        return -1;
    }

    p2p.header_len =
        (size_t)(d - p2p.payload);
    p2p.chunk_count = chunk_count;

    p2p.chunk_offsets = calloc(
        chunk_count, sizeof(size_t));
    p2p.chunk_sizes = calloc(
        chunk_count, sizeof(uint32_t));

    if (!p2p.chunk_offsets ||
        !p2p.chunk_sizes) {
        free(p2p.chunk_offsets);
        free(p2p.chunk_sizes);
        p2p.chunk_offsets = NULL;
        p2p.chunk_sizes = NULL;
        return -1;
    }

    const uint8_t *cp = d;
    size_t cr = rem;

    for (uint32_t i = 0;
         i < chunk_count; i++) {
        if (cr < 8) return -1;

        p2p.chunk_offsets[i] =
            (size_t)(cp - p2p.payload);

        uint32_t ctlen = rd32(cp + 4);
        size_t total = 4 + 4 +
            AES_IV_LEN + AES_TAG_LEN +
            ctlen;
        p2p.chunk_sizes[i] =
            (uint32_t)total;

        if (cr < total) return -1;
        cp += total;
        cr -= total;
    }

    gui_post_log(log_target,
        "P2P parsed: %u chunks, "
        "header=%zu bytes",
        chunk_count, p2p.header_len);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * SUB-TOR WAIT THREAD HELPER
 * ══════════════════════════════════════════════════════════════ */

typedef struct {
    int idx;
    int lt;
} P2PSubWaitArg;

static void *p2p_sub_wait_fn(void *arg)
{
    P2PSubWaitArg *w = arg;
    p2p_wait_sub_tor(w->idx,
        P2P_ONION_TIMEOUT, w->lt);
    free(w);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * SENDER THREAD
 * ══════════════════════════════════════════════════════════════ */

typedef struct {
    char *filepath;
    char *password;
    int   num_subs;
    int   log_target;
} P2PSendArgs;

static void *p2p_sender_thread(void *arg)
{
    P2PSendArgs *sa = arg;
    char *filepath = sa->filepath;
    char *password = sa->password;
    int   num_subs = sa->num_subs;
    int   lt       = sa->log_target;
    free(sa);

    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_log(lt,
        "P2P v2 — Parallel Tor Sender");
    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_progress(lt, 0.05);

    /* ── Step 1: Encrypt ───────────────────── */

    gui_post_log(lt,
        "Step 1: Encrypting file...");

    Buf payload;
    buf_init(&payload);
    char file_id[FILE_ID_HEX_LEN + 1] = {0};

    if (protocol_build_upload(filepath,
            password, &payload, file_id,
            lt) != 0) {
        gui_post_log(lt,
            "Encryption failed");
        goto fail;
    }

    /* Store in P2P state */
    pthread_mutex_lock(&p2p.mutex);

    if (p2p.payload) free(p2p.payload);
    if (p2p.chunk_offsets)
        free(p2p.chunk_offsets);
    if (p2p.chunk_sizes)
        free(p2p.chunk_sizes);

    p2p.payload = payload.data;
    p2p.payload_len = payload.len;
    payload.data = NULL;
    payload.len = 0;
    payload.cap = 0;

    strncpy(p2p.file_id, file_id,
            FILE_ID_HEX_LEN);

    /* Extract pw salt/verify from payload */
    memcpy(p2p.pw_salt,
           p2p.payload + 8, SALT_LEN);
    memcpy(p2p.pw_verify,
           p2p.payload + 8 + SALT_LEN,
           HASH_LEN);

    const char *base =
        strrchr(filepath, '/');
    base = base ? base + 1 : filepath;
    strncpy(p2p.filename, base,
            sizeof(p2p.filename) - 1);

    struct stat fst;
    if (stat(filepath, &fst) == 0)
        p2p.filesize = (size_t)fst.st_size;

    pthread_mutex_unlock(&p2p.mutex);

    gui_post_log(lt, "File ID: %s", file_id);
    gui_post_progress(lt, 0.15);

    /* ── Step 2: Parse chunks ──────────────── */

    gui_post_log(lt,
        "Step 2: Parsing chunk map...");

    if (p2p_parse_chunk_map(lt) != 0) {
        gui_post_log(lt,
            "Failed to parse chunk map");
        goto fail;
    }

    gui_post_progress(lt, 0.2);

    /* ── Step 3: Sub-servers ───────────────── */

    if (num_subs <= 0)
        num_subs = P2P_DEFAULT_SUBS;
    if (num_subs > P2P_MAX_SUBS)
        num_subs = P2P_MAX_SUBS;

    gui_post_log(lt,
        "Step 3: Starting %d sub-servers...",
        num_subs);

    mkdir_p(P2P_STORE_DIR, 0700);

    pthread_mutex_lock(&p2p.subs_mutex);
    p2p.num_subs = num_subs;
    for (int i = 0; i < num_subs; i++) {
        memset(&p2p.subs[i], 0,
               sizeof(P2PSubServer));
        p2p.subs[i].port =
            P2P_SUB_PORT_BASE + i;
    }
    pthread_mutex_unlock(&p2p.subs_mutex);

    int started = 0;
    for (int i = 0; i < num_subs; i++) {
        if (p2p_start_sub(i, lt) == 0)
            started++;
    }

    gui_post_log(lt,
        "%d/%d sub-servers started",
        started, num_subs);

    if (started == 0) {
        gui_post_log(lt,
            "No sub-servers — abort");
        goto fail;
    }

    gui_post_progress(lt, 0.25);

    /* ── Step 4: Distribute ────────────────── */

    gui_post_log(lt,
        "Step 4: Distributing chunks...");
    p2p_distribute_chunks(lt);

    gui_post_progress(lt, 0.6);

    /* ── Step 5: Main HTTP server ──────────── */

    gui_post_log(lt,
        "Step 5: Starting main server...");

    struct sockaddr_in main_bind;
    memset(&main_bind, 0,
           sizeof(main_bind));
    main_bind.sin_family = AF_INET;
    main_bind.sin_port =
        htons(P2P_MAIN_PORT);
    main_bind.sin_addr.s_addr =
        htonl(INADDR_LOOPBACK);

    p2p.main_daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_THREAD_PER_CONNECTION |
        MHD_USE_ERROR_LOG,
        P2P_MAIN_PORT, NULL, NULL,
        &p2p_main_handler, NULL,
        MHD_OPTION_CONNECTION_LIMIT,
        (unsigned int)16,
        MHD_OPTION_CONNECTION_TIMEOUT,
        (unsigned int)300,
        MHD_OPTION_CONNECTION_MEMORY_LIMIT,
        (size_t)(512 * 1024 * 1024),
        MHD_OPTION_SOCK_ADDR,
        (struct sockaddr *)&main_bind,
        MHD_OPTION_END);

    if (!p2p.main_daemon) {
        gui_post_log(lt,
            "Cannot bind port %d",
            P2P_MAIN_PORT);
        goto fail;
    }

    p2p.running = 1;

    char primary[256];
    get_primary_ip(primary,
                   sizeof(primary));
    char lan_display[512];
    snprintf(lan_display,
             sizeof(lan_display),
             "%s:%d (LAN)",
             primary, P2P_MAIN_PORT);
    gui_post_log(lt,
        "LAN: %s", lan_display);
    gui_post_address(lt, lan_display);

    gui_post_progress(lt, 0.65);

    /* ── Step 6: Tor hidden services ───────── */

    gui_post_log(lt,
        "Step 6: Starting Tor services...");

    /* Main onion — wait for PUBLICATION */
    if (p2p_start_main_tor(P2P_MAIN_PORT,
                           lt) == 0) {
        gui_post_log(lt,
            "Waiting for main .onion "
            "publication (up to %ds)...",
            P2P_ONION_TIMEOUT);

        if (p2p_wait_main_tor(
                P2P_ONION_TIMEOUT,
                lt) == 0) {
            gui_post_log(lt,
                "══════════════════════"
                "═════════════════");
            gui_post_log(lt,
                "\xF0\x9F\x94\x97 P2P "
                "ONION: %s",
                p2p.main_onion);
            gui_post_log(lt,
                "══════════════════════"
                "═════════════════");
            gui_post_address(lt,
                p2p.main_onion);
        }
    }

    gui_post_progress(lt, 0.75);

    /* Sub-server onions */
    gui_post_log(lt,
        "Starting %d sub-server Tor "
        "hidden services...", started);

    int tor_launched = 0;
    for (int i = 0; i < num_subs; i++) {
        pthread_mutex_lock(
            &p2p.subs_mutex);
        int active = p2p.subs[i].active;
        pthread_mutex_unlock(
            &p2p.subs_mutex);
        if (!active) continue;

        if (p2p_start_sub_tor(i, lt) == 0)
            tor_launched++;

        if (i < num_subs - 1)
            usleep(1000000);
    }

    if (tor_launched > 0) {
        gui_post_log(lt,
            "Waiting for %d sub .onion "
            "publications...",
            tor_launched);

        pthread_t *wt = malloc(
            (size_t)num_subs *
            sizeof(pthread_t));
        int *wv = calloc(
            (size_t)num_subs,
            sizeof(int));

        for (int i = 0; i < num_subs;
             i++) {
            pthread_mutex_lock(
                &p2p.subs_mutex);
            int has_tor =
                (p2p.subs[i].tor_pid > 0);
            pthread_mutex_unlock(
                &p2p.subs_mutex);
            if (!has_tor) continue;

            P2PSubWaitArg *wa =
                malloc(sizeof(*wa));
            wa->idx = i;
            wa->lt = lt;

            pthread_create(&wt[i], NULL,
                p2p_sub_wait_fn, wa);
            wv[i] = 1;
        }

        for (int i = 0; i < num_subs; i++)
            if (wv[i])
                pthread_join(wt[i], NULL);

        free(wt);
        free(wv);
    }

    /* Count ready */
    int tor_ready = 0;
    pthread_mutex_lock(&p2p.subs_mutex);
    for (int i = 0; i < p2p.num_subs; i++)
        if (p2p.subs[i].tor_ready)
            tor_ready++;
    pthread_mutex_unlock(&p2p.subs_mutex);

    gui_post_progress(lt, 0.95);

    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_log(lt,
        "\xE2\x9C\x93 P2P Sender ready!");
    gui_post_log(lt,
        "  File:      %s", p2p.filename);
    char sz[64];
    human_size(p2p.filesize, sz,
               sizeof(sz));
    gui_post_log(lt,
        "  Size:      %s", sz);
    gui_post_log(lt,
        "  Chunks:    %u",
        p2p.chunk_count);
    gui_post_log(lt,
        "  Sub-servs: %d", started);
    gui_post_log(lt,
        "  Tor onions: %d + 1 main",
        tor_ready);

    if (p2p.main_tor_ready)
        gui_post_log(lt,
            "  Address:   %s",
            p2p.main_onion);
    else
        gui_post_log(lt,
            "  Address:   %s:%d (LAN)",
            primary, P2P_MAIN_PORT);

    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_log(lt,
        "Waiting for peer to connect...");
    gui_post_progress(lt, 1.0);

fail:
    buf_free(&payload);
    if (password) {
        secure_wipe(password,
                    strlen(password));
        free(password);
    }
    free(filepath);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * PUBLIC: START SENDER
 * ══════════════════════════════════════════════════════════════ */

void p2p_start_sender(const char *filepath,
                      const char *password,
                      int num_subs,
                      int log_target)
{
    if (p2p.running) {
        gui_post_log(log_target,
            "P2P already running");
        return;
    }

    memset(&p2p, 0, sizeof(p2p));
    pthread_mutex_init(&p2p.mutex, NULL);
    pthread_mutex_init(
        &p2p.subs_mutex, NULL);

    P2PSendArgs *sa =
        malloc(sizeof(P2PSendArgs));
    sa->filepath = strdup(filepath);
    sa->password = strdup(password);
    sa->num_subs = num_subs;
    sa->log_target = log_target;

    pthread_t t;
    pthread_create(&t, NULL,
        p2p_sender_thread, sa);
    pthread_detach(t);
}

/* ══════════════════════════════════════════════════════════════
 * PUBLIC: STOP SENDER
 * ══════════════════════════════════════════════════════════════ */

void p2p_stop_sender(int log_target)
{
    gui_post_log(log_target,
        "Stopping P2P sender...");

    if (p2p.main_daemon) {
        MHD_stop_daemon(p2p.main_daemon);
        p2p.main_daemon = NULL;
    }

    if (p2p.main_tor_pid > 0) {
        kill(p2p.main_tor_pid, SIGTERM);
        for (int i = 0; i < 10; i++) {
            int status;
            if (waitpid(
                    p2p.main_tor_pid,
                    &status,
                    WNOHANG) > 0)
                break;
            usleep(500000);
        }
        kill(p2p.main_tor_pid, SIGKILL);
        waitpid(p2p.main_tor_pid,
                NULL, 0);
        p2p.main_tor_pid = 0;
    }

    /* SIGTERM all sub Tors */
    pthread_mutex_lock(&p2p.subs_mutex);
    for (int i = 0; i < p2p.num_subs; i++)
        if (p2p.subs[i].tor_pid > 0)
            kill(p2p.subs[i].tor_pid,
                 SIGTERM);
    pthread_mutex_unlock(&p2p.subs_mutex);

    usleep(2000000);

    /* Force kill + stop daemons */
    pthread_mutex_lock(&p2p.subs_mutex);
    for (int i = 0; i < p2p.num_subs; i++) {
        if (p2p.subs[i].tor_pid > 0) {
            int status;
            if (waitpid(
                    p2p.subs[i].tor_pid,
                    &status,
                    WNOHANG) <= 0) {
                kill(p2p.subs[i].tor_pid,
                     SIGKILL);
                waitpid(
                    p2p.subs[i].tor_pid,
                    NULL, 0);
            }
            p2p.subs[i].tor_pid = 0;
        }
        if (p2p.subs[i].daemon) {
            MHD_stop_daemon(
                p2p.subs[i].daemon);
            p2p.subs[i].daemon = NULL;
        }
        p2p.subs[i].active = 0;
    }
    pthread_mutex_unlock(&p2p.subs_mutex);

    pthread_mutex_lock(&p2p.mutex);
    if (p2p.payload) {
        free(p2p.payload);
        p2p.payload = NULL;
    }
    if (p2p.chunk_offsets) {
        free(p2p.chunk_offsets);
        p2p.chunk_offsets = NULL;
    }
    if (p2p.chunk_sizes) {
        free(p2p.chunk_sizes);
        p2p.chunk_sizes = NULL;
    }
    p2p.payload_len = 0;
    p2p.chunk_count = 0;
    p2p.running = 0;
    pthread_mutex_unlock(&p2p.mutex);

    pthread_mutex_destroy(&p2p.mutex);
    pthread_mutex_destroy(
        &p2p.subs_mutex);

    gui_post_log(log_target,
        "P2P sender stopped");
    gui_post_progress(log_target, 0.0);
}

/* ══════════════════════════════════════════════════════════════
 * RECEIVER
 *
 * KEY FIXES:
 * 1. Longer timeouts for .onion first connect
 * 2. Retry ping with backoff
 * 3. Robust file_id extraction from JSON
 * 4. Start Tor pool BEFORE fetching server list
 * 5. Use /p2p-servers with correct proxy
 * ══════════════════════════════════════════════════════════════ */

typedef struct {
    char *addr;
    char *password;
    int   log_target;
} P2PRecvArgs;

static int is_onion(const char *addr)
{
    return (addr && strstr(addr, ".onion"));
}

static int p2p_find_socks_port(
    char *proxy_out, size_t sz)
{
    int ports[] = { 9050, 9150, 0 };
    for (int i = 0; ports[i]; i++) {
        int s = socket(AF_INET,
            SOCK_STREAM, 0);
        if (s < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port =
            htons((uint16_t)ports[i]);
        addr.sin_addr.s_addr =
            htonl(INADDR_LOOPBACK);
        struct timeval tv = {2, 0};
        setsockopt(s, SOL_SOCKET,
            SO_SNDTIMEO, &tv, sizeof(tv));
        int ok = (connect(s,
            (struct sockaddr *)&addr,
            sizeof(addr)) == 0);
        close(s);
        if (ok) {
            snprintf(proxy_out, sz,
                "socks5h://127.0.0.1:%d",
                ports[i]);
            return ports[i];
        }
    }
    return 0;
}

/* ── Extract file_id from JSON ─────────────────────────────── */

static int extract_file_id_from_json(
    const char *json, size_t json_len,
    char *fid_out)
{
    /* Find "file_id":"<64 hex chars>" */
    const char *needle = "\"file_id\":\"";
    size_t needle_len = strlen(needle);

    for (size_t i = 0;
         i + needle_len +
             FILE_ID_HEX_LEN + 1 <=
             json_len;
         i++) {
        if (memcmp(json + i, needle,
                   needle_len) == 0) {
            const char *start =
                json + i + needle_len;

            /* Validate hex */
            int valid = 1;
            for (int j = 0;
                 j < FILE_ID_HEX_LEN;
                 j++) {
                char c = start[j];
                if (!((c >= '0' &&
                       c <= '9') ||
                      (c >= 'a' &&
                       c <= 'f') ||
                      (c >= 'A' &&
                       c <= 'F'))) {
                    valid = 0;
                    break;
                }
            }

            if (valid &&
                start[FILE_ID_HEX_LEN]
                    == '"') {
                memcpy(fid_out, start,
                       FILE_ID_HEX_LEN);
                fid_out[
                    FILE_ID_HEX_LEN] = '\0';
                return 0;
            }
        }
    }
    return -1;
}

/* ══════════════════════════════════════════════════════════════
 * RECEIVER THREAD
 * ══════════════════════════════════════════════════════════════ */

static void *p2p_recv_thread(void *arg)
{
    P2PRecvArgs *ra = arg;
    char *addr     = ra->addr;
    char *password = ra->password;
    int   lt       = ra->log_target;
    free(ra);

    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_log(lt,
        "P2P v2 — Parallel Tor Receiver");
    gui_post_log(lt,
        "══════════════════════════"
        "═════════════");
    gui_post_progress(lt, 0.05);

    struct timeval dl_start;
    gettimeofday(&dl_start, NULL);

    int onion = is_onion(addr);
    char main_proxy[256] = {0};
    const char *mp = NULL;

    if (onion) {
        int port = p2p_find_socks_port(
            main_proxy,
            sizeof(main_proxy));
        if (port > 0) {
            mp = main_proxy;
            gui_post_log(lt,
                "Tor SOCKS5 on port %d",
                port);
        } else {
            gui_post_log(lt,
                "ERROR: .onion needs Tor!");
            goto done;
        }
    }

    /* ── Step 1: Ping with retries ─────────── */

    char file_id[FILE_ID_HEX_LEN + 1] = {0};

    gui_post_log(lt,
        "Step 1: Connecting to peer...");

    /* FIX: Retry ping with increasing timeout
       First connect to .onion can take 30-90s
       because circuit needs to be built */
    {
        int ping_ok = 0;
        int max_ping_attempts = onion ? 4 : 2;
        long ping_timeouts[] =
            { 90, 120, 150, 180 };

        for (int attempt = 0;
             attempt < max_ping_attempts;
             attempt++) {

            if (attempt > 0)
                gui_post_log(lt,
                    "  Retry %d/%d "
                    "(timeout %lds)...",
                    attempt + 1,
                    max_ping_attempts,
                    ping_timeouts[attempt]);

            char url[1024];
            snprintf(url, sizeof(url),
                "http://%s/p2p-ping", addr);

            CURL *c = curl_easy_init();
            if (!c) continue;

            if (mp)
                curl_easy_setopt(c,
                    CURLOPT_PROXY, mp);

            Buf resp;
            buf_init(&resp);
            P2PCurlCtx ctx = {
                .buf = &resp
            };

            curl_easy_setopt(c,
                CURLOPT_URL, url);
            curl_easy_setopt(c,
                CURLOPT_WRITEFUNCTION,
                p2p_write_cb);
            curl_easy_setopt(c,
                CURLOPT_WRITEDATA, &ctx);
            curl_easy_setopt(c,
                CURLOPT_TIMEOUT,
                ping_timeouts[attempt]);
            curl_easy_setopt(c,
                CURLOPT_CONNECTTIMEOUT,
                ping_timeouts[attempt]);

            CURLcode res =
                curl_easy_perform(c);
            long code = 0;
            curl_easy_getinfo(c,
                CURLINFO_RESPONSE_CODE,
                &code);
            curl_easy_cleanup(c);

            if (res == CURLE_OK &&
                code == 200 &&
                resp.len > 0) {

                /* Parse response */
                char *json =
                    malloc(resp.len + 1);
                memcpy(json, resp.data,
                       resp.len);
                json[resp.len] = '\0';
                gui_post_log(lt,
                    "\xE2\x9C\x93 Peer: %s",
                    json);

                /* Extract file_id */
                if (extract_file_id_from_json(
                        json, resp.len,
                        file_id) == 0) {
                    gui_post_log(lt,
                        "File ID: %.16s...",
                        file_id);
                }

                free(json);
                buf_free(&resp);
                ping_ok = 1;
                break;
            }

            gui_post_log(lt,
                "  Ping attempt %d: %s "
                "(HTTP %ld)",
                attempt + 1,
                curl_easy_strerror(res),
                code);
            buf_free(&resp);

            if (attempt <
                max_ping_attempts - 1)
                sleep(5);
        }

        if (!ping_ok) {
            gui_post_log(lt,
                "Cannot reach peer after "
                "%d attempts",
                max_ping_attempts);
            goto done;
        }
    }

    gui_post_progress(lt, 0.1);

    /* ── Step 2: Get sub-server list ───────── */

    /* FIX: Use /p2p-servers endpoint
       (not /servers which is for main server) */

    gui_post_log(lt,
        "Step 2: Getting sub-servers...");

    SubServerList servers;
    int nsrv = 0;
    int max_srv_attempts = onion ? 6 : 2;

    for (int sa = 0;
         sa < max_srv_attempts &&
             nsrv <= 0;
         sa++) {
        if (sa > 0) {
            gui_post_log(lt,
                "  Waiting for sub-servers "
                "(%d/%d, 15s)...",
                sa + 1, max_srv_attempts);
            sleep(15);
        }

        /* FIX: Use correct endpoint
           parallel_get_server_list uses
           /servers but P2P uses /p2p-servers.
           We do it manually here. */
        {
            char url[1024];
            snprintf(url, sizeof(url),
                "http://%s/p2p-servers",
                addr);

            CURL *c = curl_easy_init();
            if (!c) continue;

            if (mp)
                curl_easy_setopt(c,
                    CURLOPT_PROXY, mp);

            Buf resp;
            buf_init(&resp);
            P2PCurlCtx ctx = {
                .buf = &resp
            };

            curl_easy_setopt(c,
                CURLOPT_URL, url);
            curl_easy_setopt(c,
                CURLOPT_WRITEFUNCTION,
                p2p_write_cb);
            curl_easy_setopt(c,
                CURLOPT_WRITEDATA, &ctx);
            curl_easy_setopt(c,
                CURLOPT_TIMEOUT,
                onion ? 60L : 15L);
            curl_easy_setopt(c,
                CURLOPT_CONNECTTIMEOUT,
                onion ? 30L : 10L);

            CURLcode res =
                curl_easy_perform(c);
            long code = 0;
            curl_easy_getinfo(c,
                CURLINFO_RESPONSE_CODE,
                &code);
            curl_easy_cleanup(c);

            if (res == CURLE_OK &&
                code == 200 &&
                resp.len > 0) {

                /* Parse lines:
                   host:port\n */
                char *copy =
                    malloc(resp.len + 1);
                memcpy(copy, resp.data,
                       resp.len);
                copy[resp.len] = '\0';

                memset(&servers, 0,
                       sizeof(servers));

                char *saveptr = NULL;
                char *line = strtok_r(
                    copy, "\n", &saveptr);

                while (line &&
                    servers.count <
                        PARALLEL_MAX_SERVERS) {

                    while (*line == ' ')
                        line++;
                    if (*line == '\0') {
                        line = strtok_r(
                            NULL, "\n",
                            &saveptr);
                        continue;
                    }

                    char *colon =
                        strrchr(line, ':');
                    if (colon &&
                        colon != line) {
                        SubServerEntry *e =
                            &servers.entries[
                                servers.count
                            ];
                        size_t hlen =
                            (size_t)(colon -
                                     line);
                        if (hlen >=
                            sizeof(e->host))
                            hlen =
                                sizeof(
                                    e->host)
                                - 1;
                        memcpy(e->host,
                               line, hlen);
                        e->host[hlen] = '\0';
                        e->port =
                            atoi(colon + 1);
                        e->active = 1;
                        if (e->port > 0)
                            servers.count++;
                    }

                    line = strtok_r(
                        NULL, "\n",
                        &saveptr);
                }

                free(copy);
                nsrv = servers.count;
            }

            buf_free(&resp);
        }
    }

    if (nsrv <= 0) {
        gui_post_log(lt,
            "No sub-servers — "
            "single-conn fallback");
        goto single_fallback;
    }

    gui_post_log(lt,
        "%d sub-servers found", nsrv);
    for (int i = 0; i < nsrv && i < 3; i++)
        gui_post_log(lt,
            "  Sub[%d]: %s:%d",
            i, servers.entries[i].host,
            servers.entries[i].port);

    gui_post_progress(lt, 0.15);

    /* ── Step 3: Start Tor pool ────────────── */

    int num_pool_proxies = 0;
    const char *pool_proxies[TOR_POOL_MAX];

    if (onion) {
        gui_post_log(lt,
            "Step 3: Starting Tor "
            "proxy pool...");

        int pool_count = nsrv;
        if (pool_count > TOR_POOL_MAX)
            pool_count = TOR_POOL_MAX;
        if (pool_count < 4)
            pool_count = 4;

        int ready = tor_pool_start(
            pool_count, lt);
        if (ready > 0) {
            num_pool_proxies =
                tor_pool_get_all_proxies(
                    pool_proxies,
                    TOR_POOL_MAX);
            gui_post_log(lt,
                "\xE2\x9C\x93 %d circuits",
                num_pool_proxies);
        } else {
            gui_post_log(lt,
                "Pool failed — single");
            if (mp) {
                pool_proxies[0] = mp;
                num_pool_proxies = 1;
            }
        }
    }

    gui_post_progress(lt, 0.2);

    /* ── Step 4: Get metadata ──────────────── */

    if (file_id[0] == '\0') {
        gui_post_log(lt,
            "No file_id — cannot do "
            "parallel");
        goto single_fallback;
    }

    gui_post_log(lt,
        "Step 4: Requesting metadata...");

    Buf meta_resp;
    buf_init(&meta_resp);
    int meta_ok = 0;

    {
        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s/p2p-download", addr);

        CURL *c = curl_easy_init();
        if (!c) goto single_fallback;

        if (mp)
            curl_easy_setopt(c,
                CURLOPT_PROXY, mp);

        P2PCurlCtx ctx = {
            .buf = &meta_resp
        };

        curl_easy_setopt(c,
            CURLOPT_URL, url);
        curl_easy_setopt(c,
            CURLOPT_POST, 1L);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDS, password);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)strlen(password));
        curl_easy_setopt(c,
            CURLOPT_WRITEFUNCTION,
            p2p_write_cb);
        curl_easy_setopt(c,
            CURLOPT_WRITEDATA, &ctx);
        curl_easy_setopt(c,
            CURLOPT_TIMEOUT,
            onion ? 120L : 30L);
        curl_easy_setopt(c,
            CURLOPT_CONNECTTIMEOUT,
            onion ? 60L : 15L);

        CURLcode res =
            curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c,
            CURLINFO_RESPONSE_CODE,
            &code);
        curl_easy_cleanup(c);

        if (res == CURLE_OK &&
            code == 200 &&
            meta_resp.len > 8) {
            char msz[64];
            human_size(meta_resp.len,
                       msz, sizeof(msz));
            gui_post_log(lt,
                "\xE2\x9C\x93 Metadata: %s",
                msz);
            meta_ok = 1;
        } else if (code == 403) {
            gui_post_log(lt,
                "Wrong password");
            buf_free(&meta_resp);
            goto done;
        } else {
            gui_post_log(lt,
                "Metadata failed: %s "
                "(HTTP %ld)",
                curl_easy_strerror(res),
                code);
            buf_free(&meta_resp);
            goto single_fallback;
        }
    }

    gui_post_progress(lt, 0.25);

    /* ── Step 5: Parse + parallel download ─── */

    {
        /* Parse chunk count from metadata */
        const uint8_t *xp = meta_resp.data;
        size_t xrem = meta_resp.len;
        int xok = 1;
        uint32_t xtmp = 0;

        #define XS(n) do { \
            if (!xok) break; \
            if (xrem < (size_t)(n)) \
                xok = 0; \
            else { xp += (n); \
                   xrem -= (n); } \
        } while(0)

        #define XR(v) do { \
            if (!xok) break; \
            if (xrem < 4) xok = 0; \
            else { (v) = rd32(xp); \
                   xp += 4; \
                   xrem -= 4; } \
        } while(0)

        XS(4); XS(4);
        XS(SALT_LEN); XS(HASH_LEN);
        XR(xtmp); XS(xtmp);
        XS(AES_IV_LEN); XS(AES_TAG_LEN);
        XR(xtmp); XS(xtmp);
        XR(xtmp); XS(xtmp);
        XR(xtmp); XS(xtmp);
        XS(8);

        uint32_t chunk_count = 0;
        XR(chunk_count);

        #undef XS
        #undef XR

        if (!xok || chunk_count == 0 ||
            chunk_count > MAX_CHUNKS) {
            gui_post_log(lt,
                "Metadata parse failed");
            buf_free(&meta_resp);
            goto single_fallback;
        }

        gui_post_log(lt,
            "Step 5: Downloading %u "
            "chunks via %d circuits "
            "from %d servers...",
            chunk_count,
            num_pool_proxies, nsrv);

        uint32_t *chunk_sizes = calloc(
            chunk_count,
            sizeof(uint32_t));

        Buf assembled;
        buf_init(&assembled);
        buf_reserve(&assembled,
            meta_resp.len +
            (size_t)chunk_count *
                CHUNK_SIZE);
        buf_add(&assembled,
                meta_resp.data,
                meta_resp.len);

        int prc =
            parallel_download_chunks(
                addr,
                num_pool_proxies > 0 ?
                    pool_proxies : NULL,
                num_pool_proxies,
                &servers, file_id,
                (int)chunk_count,
                chunk_sizes,
                &assembled, lt);

        free(chunk_sizes);
        buf_free(&meta_resp);

        if (prc == 0) {
            char asz[64];
            human_size(assembled.len,
                       asz, sizeof(asz));
            gui_post_log(lt,
                "Complete (%s) — "
                "decrypting...", asz);
            gui_post_progress(lt, 0.7);

            int drc =
                protocol_parse_download(
                    assembled.data,
                    assembled.len,
                    password, lt);

            buf_free(&assembled);

            if (drc == 0) {
                parallel_free_server_list(
                    &servers);

                struct timeval dl_end;
                gettimeofday(&dl_end, NULL);
                double elapsed =
                    (double)(dl_end.tv_sec -
                        dl_start.tv_sec) +
                    (double)(dl_end.tv_usec -
                        dl_start.tv_usec)
                    / 1e6;

                gui_post_log(lt,
                    "═══════════════════"
                    "════════════════"
                    "════");
                gui_post_log(lt,
                    "\xE2\x9C\x93 P2P "
                    "complete!");
                gui_post_log(lt,
                    "  Time:     %.1fs",
                    elapsed);
                gui_post_log(lt,
                    "  Circuits: %d",
                    num_pool_proxies);
                gui_post_log(lt,
                    "  Servers:  %d",
                    nsrv);
                gui_post_log(lt,
                    "═══════════════════"
                    "════════════════"
                    "════");
                gui_post_progress(lt, 1.0);
                goto done;
            }

            gui_post_log(lt,
                "Decrypt failed");
        } else {
            buf_free(&assembled);
            gui_post_log(lt,
                "Parallel download failed");
        }

        parallel_free_server_list(&servers);
    }

    /* ── SINGLE-CONN FALLBACK ──────────────── */

single_fallback:
    gui_post_log(lt,
        "Single-connection fallback...");
    {
        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s/p2p-download-full",
            addr);

        CURL *c = curl_easy_init();
        if (!c) goto done;

        if (mp)
            curl_easy_setopt(c,
                CURLOPT_PROXY, mp);

        Buf resp;
        buf_init(&resp);
        P2PCurlCtx ctx = { .buf = &resp };

        curl_easy_setopt(c,
            CURLOPT_URL, url);
        curl_easy_setopt(c,
            CURLOPT_POST, 1L);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDS, password);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)strlen(password));
        curl_easy_setopt(c,
            CURLOPT_WRITEFUNCTION,
            p2p_write_cb);
        curl_easy_setopt(c,
            CURLOPT_WRITEDATA, &ctx);
        curl_easy_setopt(c,
            CURLOPT_TIMEOUT, 600L);
        curl_easy_setopt(c,
            CURLOPT_CONNECTTIMEOUT,
            onion ? 90L : 15L);
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(c,
            CURLOPT_BUFFERSIZE, 262144L);

        gui_post_progress(lt, 0.2);

        CURLcode res =
            curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c,
            CURLINFO_RESPONSE_CODE,
            &code);
        curl_easy_cleanup(c);

        if (res != CURLE_OK) {
            gui_post_log(lt,
                "Transfer error: %s",
                curl_easy_strerror(res));
            buf_free(&resp);
            goto done;
        }

        if (code == 403) {
            gui_post_log(lt,
                "Wrong password");
            buf_free(&resp);
            goto done;
        }

        if (code != 200) {
            gui_post_log(lt,
                "HTTP %ld", code);
            buf_free(&resp);
            goto done;
        }

        char sz[64];
        human_size(resp.len, sz,
                   sizeof(sz));
        gui_post_log(lt,
            "Received %s — decrypting...",
            sz);
        gui_post_progress(lt, 0.5);

        int drc = protocol_parse_download(
            resp.data, resp.len,
            password, lt);

        buf_free(&resp);

        if (drc == 0) {
            struct timeval dl_end;
            gettimeofday(&dl_end, NULL);
            double elapsed =
                (double)(dl_end.tv_sec -
                    dl_start.tv_sec) +
                (double)(dl_end.tv_usec -
                    dl_start.tv_usec) / 1e6;

            gui_post_log(lt,
                "\xE2\x9C\x93 P2P complete"
                " (%.1fs, single-conn)",
                elapsed);
        } else {
            gui_post_log(lt,
                "Decrypt failed");
        }

        gui_post_progress(lt, 1.0);
    }

done:
    if (password) {
        secure_wipe(password,
                    strlen(password));
        free(password);
    }
    free(addr);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * PUBLIC: RECEIVE
 * ══════════════════════════════════════════════════════════════ */

void p2p_receive_file(const char *addr,
                      const char *password,
                      int log_target)
{
    P2PRecvArgs *ra =
        malloc(sizeof(P2PRecvArgs));
    ra->addr = strdup(addr);
    ra->password = strdup(password);
    ra->log_target = log_target;

    pthread_t t;
    pthread_create(&t, NULL,
        p2p_recv_thread, ra);
    pthread_detach(t);
}

/* ══════════════════════════════════════════════════════════════
 * QUERY STATE
 * ══════════════════════════════════════════════════════════════ */

int p2p_is_running(void)
{
    return p2p.running;
}

const char *p2p_get_onion_address(void)
{
    if (p2p.main_tor_ready &&
        p2p.main_onion[0])
        return p2p.main_onion;
    return NULL;
}