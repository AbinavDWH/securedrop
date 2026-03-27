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

#include "storage.h"
#include "crypto.h"
#include "gui_helpers.h"

#include <dirent.h>
#include <curl/curl.h>
#include <pthread.h>
#include <errno.h>

/* ──────────────────────────────────────────────────────────────
 * CONFIGURATION
 * ────────────────────────────────────────────────────────────── */

#define STORE_BATCH_SIZE       8   /* parallel disk/net writes */
#define STORE_CURL_TIMEOUT     15  /* seconds per chunk store  */
#define STORE_CURL_CONNECT     5
#define RETRIEVE_CURL_TIMEOUT  20
#define RETRIEVE_CURL_CONNECT  5
#define STORE_RETRIES          3
#define STORE_RETRY_DELAY_MS   500
#define MHD_THREAD_POOL_SIZE   4   /* threads per sub-server   */
#define MHD_CONN_LIMIT         64
#define STREAM_WRITE_THRESHOLD 0   /* 0 = always stream        */



static int validate_file_id(const char *fid)
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


/* ──────────────────────────────────────────────────────────────
 * INITIALIZATION
 * ────────────────────────────────────────────────────────────── */




void storage_init(void)
{
    mkdir_p(KEY_DIR, 0700);
    mkdir_p(STORE_DIR, 0700);
    mkdir_p(META_DIR, 0700);
    mkdir_p(OUTPUT_DIR, 0700);

    pthread_mutex_init(&app.subserver_mutex, NULL);
    pthread_mutex_init(&app.stored_mutex, NULL);

    if (!app.sub_servers) {
        app.sub_servers_cap = 64;
        app.sub_servers = calloc(
            (size_t)app.sub_servers_cap,
            sizeof(SubServer));
        app.num_sub_servers = 0;
    }

    if (!app.stored_files) {
        app.stored_files_cap = 64;
        app.stored_files = calloc(
            (size_t)app.stored_files_cap,
            sizeof(StoredFileMeta));
        app.stored_file_count = 0;
    }
}

/* ── Grow sub-server array if needed ─────────── */

static int ensure_subserver_capacity(void)
{
    if (app.num_sub_servers < app.sub_servers_cap)
        return 0;

    int new_cap = app.sub_servers_cap * 2;
    if (new_cap > MAX_SUB_SERVERS)
        new_cap = MAX_SUB_SERVERS;

    if (app.num_sub_servers >= new_cap)
        return -1;

    SubServer *new_arr = realloc(
        app.sub_servers,
        (size_t)new_cap * sizeof(SubServer));

    if (!new_arr) return -1;

    memset(&new_arr[app.sub_servers_cap], 0,
           (size_t)(new_cap - app.sub_servers_cap)
           * sizeof(SubServer));

    app.sub_servers = new_arr;
    app.sub_servers_cap = new_cap;
    return 0;
}

 int ensure_stored_capacity(void)
{
    if (app.stored_file_count < app.stored_files_cap)
        return 0;

    int new_cap = app.stored_files_cap * 2;
    if (new_cap > MAX_STORED_FILES)
        new_cap = MAX_STORED_FILES;

    if (app.stored_file_count >= new_cap)
        return -1;

    StoredFileMeta *new_arr = realloc(
        app.stored_files,
        (size_t)new_cap * sizeof(StoredFileMeta));

    if (!new_arr) return -1;

    memset(&new_arr[app.stored_files_cap], 0,
           (size_t)(new_cap - app.stored_files_cap)
           * sizeof(StoredFileMeta));

    app.stored_files = new_arr;
    app.stored_files_cap = new_cap;
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * PATH HELPERS
 * ────────────────────────────────────────────────────────────── */

static void chunk_dir_path(char *buf, size_t bufsz,
                           const char *file_id)
{
    snprintf(buf, bufsz, "%s/%.16s",
             STORE_DIR, file_id);
}

static void chunk_file_path(char *buf, size_t bufsz,
                            const char *file_id,
                            uint32_t chunk_idx)
{
    snprintf(buf, bufsz,
             "%s/%.16s/chunk_%06u.bin",
             STORE_DIR, file_id, chunk_idx);
}

static void meta_file_path(char *buf, size_t bufsz,
                           const char *file_id)
{
    snprintf(buf, bufsz, "%s/%.16s.meta",
             META_DIR, file_id);
}

/* ──────────────────────────────────────────────────────────────
 * CURL HELPERS
 * ────────────────────────────────────────────────────────────── */

typedef struct { Buf *buf; } CurlBufCtx;

static size_t curl_write_buf(void *data,
                             size_t size,
                             size_t nmemb,
                             void *userp)
{
    CurlBufCtx *ctx = userp;
    if (size != 0 && nmemb > SIZE_MAX / size)
        return 0;
    size_t total = size * nmemb;
    if (ctx->buf->len + total > (size_t)64 * 1024 * 1024)
        return 0;
    buf_add(ctx->buf, data, total);
    return total;
}

/* Discard response body */
static size_t curl_write_discard(void *data,
                                 size_t size,
                                 size_t nmemb,
                                 void *userp)
{
    (void)data; (void)userp;
    return size * nmemb;
}

/* ──────────────────────────────────────────────────────────────
 * DETERMINISTIC CHUNK → SUB-SERVER MAPPING
 *
 * Both storage_store_chunk and parallel.c now
 * use the SAME formula:
 *
 *   sub_server_index = chunk_idx % num_sub_servers
 *
 * This ensures download asks the RIGHT server
 * for each chunk without needing a routing table.
 * ────────────────────────────────────────────────────────────── */

static int chunk_to_subserver(uint32_t chunk_idx,
                              int num_servers)
{
    if (num_servers <= 0) return -1;
    return (int)(chunk_idx % (uint32_t)num_servers);
}

/* ──────────────────────────────────────────────────────────────
 * PORT VALIDATION
 * ────────────────────────────────────────────────────────────── */

int storage_validate_port(int port)
{
    if (port < SUB_PORT_BASE || port > SUB_PORT_MAX)
        return -1;

    pthread_mutex_lock(&app.subserver_mutex);
    for (int i = 0; i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].port == port) {
            pthread_mutex_unlock(
                &app.subserver_mutex);
            return -2;
        }
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * STORE CHUNK — SINGLE
 *
 * Uses deterministic routing instead of
 * least-loaded. Falls back to local disk if
 * sub-server is unavailable.
 *
 * Includes retry logic for transient failures.
 * ────────────────────────────────────────────────────────────── */

int storage_store_chunk(const char *file_id,
                        uint32_t chunk_idx,
                        const unsigned char *data,
                        size_t len,
                        int log_target)
{
    int sub_idx = -1;

    pthread_mutex_lock(&app.subserver_mutex);
    int n_servers = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    if (n_servers > 0) {
        /* Deterministic routing */
        int target = chunk_to_subserver(
            chunk_idx, n_servers);

        pthread_mutex_lock(&app.subserver_mutex);
        SubServer *ss =
            &app.sub_servers[target];
        int active = ss->active;
        char addr[256];
        int port = ss->port;

        if (active) {
            strncpy(addr, ss->address,
                    sizeof(addr) - 1);
            addr[sizeof(addr) - 1] = '\0';
        }
        pthread_mutex_unlock(
            &app.subserver_mutex);

        if (active) {
            char url[512];
            snprintf(url, sizeof(url),
                "http://%s:%d/store/%s/%u",
                addr, port, file_id, chunk_idx);

            /* Retry loop */
            for (int attempt = 0;
                 attempt < STORE_RETRIES;
                 attempt++) {

                CURL *c = curl_easy_init();
                if (!c) break;

                struct curl_slist *hdr = NULL;
                hdr = curl_slist_append(hdr,
                    "Content-Type: "
                    "application/octet-stream");

                curl_easy_setopt(c,
                    CURLOPT_URL, url);
                curl_easy_setopt(c,
                    CURLOPT_POST, 1L);
                curl_easy_setopt(c,
                    CURLOPT_POSTFIELDS, data);
                curl_easy_setopt(c,
                    CURLOPT_POSTFIELDSIZE_LARGE,
                    (curl_off_t)len);
                curl_easy_setopt(c,
                    CURLOPT_HTTPHEADER, hdr);
                curl_easy_setopt(c,
                    CURLOPT_TIMEOUT,
                    (long)STORE_CURL_TIMEOUT);
                curl_easy_setopt(c,
                    CURLOPT_CONNECTTIMEOUT,
                    (long)STORE_CURL_CONNECT);
                curl_easy_setopt(c,
                    CURLOPT_WRITEFUNCTION,
                    curl_write_discard);

                CURLcode res =
                    curl_easy_perform(c);
                long http_code = 0;
                curl_easy_getinfo(c,
                    CURLINFO_RESPONSE_CODE,
                    &http_code);

                curl_slist_free_all(hdr);
                curl_easy_cleanup(c);

                if (res == CURLE_OK &&
                    http_code == 200) {

                    pthread_mutex_lock(
                        &app.subserver_mutex);
                    app.sub_servers[target]
                        .chunk_count++;
                    pthread_mutex_unlock(
                        &app.subserver_mutex);

                    return target;
                }

                /* Retry after delay */
                if (attempt <
                    STORE_RETRIES - 1) {

                    int delay_ms =
                        STORE_RETRY_DELAY_MS *
                        (1 << attempt);
                    /* 500, 1000, 2000 ms */
                    usleep(
                        (useconds_t)delay_ms *
                        1000);
                }
            }

            gui_post_log(log_target,
                "Sub[%d] store failed after "
                "%d attempts, local fallback",
                target, STORE_RETRIES);
        }
    }

    /* ── Local fallback ─────────────────────── */
    char dir[4096];
    chunk_dir_path(dir, sizeof(dir), file_id);
    mkdir_p(dir, 0700);

    char path[4096];
    chunk_file_path(path, sizeof(path),
                    file_id, chunk_idx);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        gui_post_log(log_target,
            "Local chunk write failed: %s",
            strerror(errno));
        return -1;
    }

    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);

    if (written != len) {
        gui_post_log(log_target,
            "Partial write: %zu/%zu bytes",
            written, len);
        unlink(path);
        return -1;
    }

    return -1; /* -1 = stored locally */
}

/* ──────────────────────────────────────────────────────────────
 * STORE CHUNKS IN PARALLEL — SERVER SIDE
 *
 * Called by protocol_parse_upload to forward
 * chunks to sub-servers concurrently instead
 * of one-by-one.
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    const char          *file_id;
    uint32_t             chunk_idx;
    const unsigned char *data;
    size_t               len;
    int                  log_target;
    int                  result;  /* sub_idx or -1 */
} ChunkStoreJob;

static void *store_chunk_worker(void *arg)
{
    ChunkStoreJob *job = arg;

    job->result = storage_store_chunk(
        job->file_id, job->chunk_idx,
        job->data, job->len,
        job->log_target);

    return NULL;
}

int storage_store_chunks_parallel(
    const char *file_id,
    int chunk_count,
    const unsigned char **chunk_data,
    const size_t *chunk_lens,
    int *chunk_locations_out,
    int log_target)
{
    int failed = 0;

    /* Process in batches of STORE_BATCH_SIZE */
    for (int base = 0; base < chunk_count;
         base += STORE_BATCH_SIZE) {

        int batch_n = STORE_BATCH_SIZE;
        if (base + batch_n > chunk_count)
            batch_n = chunk_count - base;

        pthread_t threads[STORE_BATCH_SIZE];
        ChunkStoreJob jobs[STORE_BATCH_SIZE];

        /* Launch batch */
        for (int j = 0; j < batch_n; j++) {
            int ci = base + j;
            jobs[j] = (ChunkStoreJob){
                .file_id    = file_id,
                .chunk_idx  = (uint32_t)ci,
                .data       = chunk_data[ci],
                .len        = chunk_lens[ci],
                .log_target = log_target,
                .result     = -1,
            };

            pthread_create(&threads[j], NULL,
                store_chunk_worker, &jobs[j]);
        }

        /* Wait for batch */
        for (int j = 0; j < batch_n; j++) {
            pthread_join(threads[j], NULL);

            int ci = base + j;
            chunk_locations_out[ci] =
                jobs[j].result;

            if (jobs[j].result < -1)
                failed++;
        }

        /* Progress */
        int done = base + batch_n;
        gui_post_progress(log_target,
            (double)done / chunk_count);

        if (done == batch_n ||
            done % 50 == 0 ||
            done == chunk_count) {

            gui_post_log(log_target,
                "Stored %d/%d chunks",
                done, chunk_count);
        }
    }

    if (failed > 0) {
        gui_post_log(log_target,
            "%d chunks failed to store",
            failed);
        return -1;
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * RETRIEVE CHUNK
 *
 * Uses deterministic routing as primary.
 * Falls back to stored location, then
 * local disk, then brute-force search.
 * ────────────────────────────────────────────────────────────── */

int storage_retrieve_chunk(const char *file_id,
                           uint32_t chunk_idx,
                           int sub_server_idx,
                           Buf *out,
                           int log_target)
{
    /* ── Strategy 1: Deterministic routing ──── */
    pthread_mutex_lock(&app.subserver_mutex);
    int n_servers = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    int target = -1;

    if (n_servers > 0) {
        target = chunk_to_subserver(
            chunk_idx, n_servers);
    }

    /* Try targets in order:
       1. Deterministic target
       2. Stored location (sub_server_idx)
       3. Local disk */

    int targets[3];
    int n_targets = 0;

    if (target >= 0)
        targets[n_targets++] = target;
    if (sub_server_idx >= 0 &&
        sub_server_idx != target)
        targets[n_targets++] = sub_server_idx;

    for (int t = 0; t < n_targets; t++) {
        int si = targets[t];

        pthread_mutex_lock(&app.subserver_mutex);

        if (si >= app.num_sub_servers ||
            !app.sub_servers[si].active) {
            pthread_mutex_unlock(
                &app.subserver_mutex);
            continue;
        }

        char addr[256];
        int port = app.sub_servers[si].port;
        strncpy(addr,
                app.sub_servers[si].address,
                sizeof(addr) - 1);
        addr[sizeof(addr) - 1] = '\0';

        pthread_mutex_unlock(
            &app.subserver_mutex);

        char url[512];
        snprintf(url, sizeof(url),
            "http://%s:%d/retrieve/%s/%u",
            addr, port, file_id, chunk_idx);

        /* Retry loop */
        for (int attempt = 0;
             attempt < STORE_RETRIES;
             attempt++) {

            CURL *c = curl_easy_init();
            if (!c) break;

            /* Reset output buffer on retry */
            if (out->len > 0) {
                buf_free(out);
                buf_init(out);
            }

            CurlBufCtx ctx = { .buf = out };

            curl_easy_setopt(c,
                CURLOPT_URL, url);
            curl_easy_setopt(c,
                CURLOPT_WRITEFUNCTION,
                curl_write_buf);
            curl_easy_setopt(c,
                CURLOPT_WRITEDATA, &ctx);
            curl_easy_setopt(c,
                CURLOPT_TIMEOUT,
                (long)RETRIEVE_CURL_TIMEOUT);
            curl_easy_setopt(c,
                CURLOPT_CONNECTTIMEOUT,
                (long)RETRIEVE_CURL_CONNECT);

            CURLcode res =
                curl_easy_perform(c);
            long http_code = 0;
            curl_easy_getinfo(c,
                CURLINFO_RESPONSE_CODE,
                &http_code);
            curl_easy_cleanup(c);

            if (res == CURLE_OK &&
                http_code == 200 &&
                out->len > 0) {
                return 0;
            }

            if (http_code == 404)
                break; /* chunk not on this
                          server, try next */

            if (attempt <
                STORE_RETRIES - 1) {
                usleep(
                    (useconds_t)
                    STORE_RETRY_DELAY_MS *
                    1000 *
                    (useconds_t)(1 << attempt));
            }
        }
    }

    /* ── Strategy 3: Local fallback ──────────── */
    char path[4096];
    chunk_file_path(path, sizeof(path),
                    file_id, chunk_idx);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        gui_post_log(log_target,
            "Chunk %u not found anywhere",
            chunk_idx);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(fp);
        return -1;
    }

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t rd = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (rd != (size_t)sz) {
        free(buf);
        return -1;
    }

    buf_add(out, buf, (size_t)sz);
    free(buf);
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * METADATA PERSISTENCE
 * ────────────────────────────────────────────────────────────── */

int storage_save_meta(const StoredFileMeta *meta,
                      int log_target)
{
    char path[4096];
    meta_file_path(path, sizeof(path),
                   meta->file_id);
    mkdir_p(META_DIR, 0700);

    /* Write to temp file first, then rename
       for crash safety */
    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path),
             "%s.tmp", path);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        gui_post_log(log_target,
            "Cannot save meta: %s",
            strerror(errno));
        return -1;
    }

    size_t nw = fwrite(meta,
        sizeof(StoredFileMeta), 1, fp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (nw != 1) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

int storage_load_meta(const char *file_id,
                      StoredFileMeta *meta_out)
{
    char path[4096];
    meta_file_path(path, sizeof(path), file_id);

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    size_t nr = fread(meta_out,
        sizeof(StoredFileMeta), 1, fp);
    fclose(fp);
    return (nr == 1) ? 0 : -1;
}

int storage_load_all_meta(int log_target)
{
    DIR *d = opendir(META_DIR);
    if (!d) return 0;

    struct dirent *e;
    int count = 0;

    pthread_mutex_lock(&app.stored_mutex);

    while ((e = readdir(d)) != NULL &&
           app.stored_file_count <
               MAX_STORED_FILES) {
        if (e->d_name[0] == '.') continue;

        size_t nlen = strlen(e->d_name);
        if (nlen < 6 ||
            strcmp(e->d_name + nlen - 5,
                   ".meta") != 0)
            continue;

        char path[4096];
        snprintf(path, sizeof(path),
            "%s/%s", META_DIR, e->d_name);

        FILE *fp = fopen(path, "rb");
        if (!fp) continue;

        StoredFileMeta *meta =
            &app.stored_files[
                app.stored_file_count];
        size_t nr = fread(meta,
            sizeof(StoredFileMeta), 1, fp);
        fclose(fp);

        if (nr == 1) {
            meta->original_name[sizeof(meta->original_name) - 1] = '\0';
            meta->file_id[FILE_ID_HEX_LEN] = '\0';

            for (char *x = meta->original_name; *x; x++)
                if (*x == '/' || *x == '\\') *x = '_';

            if (meta->chunk_count > MAX_CHUNKS)
                meta->chunk_count = 0;

            if (meta->rsa_pub_len > sizeof(meta->rsa_pub_pem))
                meta->rsa_pub_len = 0;
            if (meta->erp_len > sizeof(meta->enc_rsa_priv))
                meta->erp_len = 0;
            if (meta->emk_len > sizeof(meta->enc_master_key))
                meta->emk_len = 0;

            app.stored_file_count++;
            count++;
        }
    }

    pthread_mutex_unlock(&app.stored_mutex);
    closedir(d);

    if (count > 0)
        gui_post_log(log_target,
            "Loaded %d stored file(s)", count);

    return count;
}

int storage_delete_file(const char *file_id,
                        int log_target)
{
    /* Delete chunks from sub-servers */
    pthread_mutex_lock(&app.stored_mutex);
    StoredFileMeta *meta = NULL;
    for (int i = 0;
         i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id) == 0) {
            meta = &app.stored_files[i];
            break;
        }
    }

    uint32_t chunk_count = 0;
    if (meta) chunk_count = meta->chunk_count;
    pthread_mutex_unlock(&app.stored_mutex);

    /* TODO: Send DELETE to sub-servers for
       distributed chunks */

    /* Delete local chunks */
    char dir[4096];
    chunk_dir_path(dir, sizeof(dir), file_id);

    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char path[4096];
            snprintf(path, sizeof(path),
                "%s/%s", dir, e->d_name);
            unlink(path);
        }
        closedir(d);
        rmdir(dir);
    }

    /* Delete metadata */
    char mp[4096];
    meta_file_path(mp, sizeof(mp), file_id);
    unlink(mp);

    /* Remove from in-memory array */
    pthread_mutex_lock(&app.stored_mutex);
    for (int i = 0;
         i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id) == 0) {
            memmove(&app.stored_files[i],
                &app.stored_files[i + 1],
                (size_t)(app.stored_file_count
                         - i - 1) *
                sizeof(StoredFileMeta));
            app.stored_file_count--;
            break;
        }
    }
    pthread_mutex_unlock(&app.stored_mutex);

    gui_post_log(log_target,
        "Deleted: %.16s...", file_id);
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * SUB-SERVER HTTP HANDLER
 *
 * Endpoints:
 *   GET  /ping                     ← circuit warmup
 *   GET  /health  or  /            ← health check
 *   POST /store/{file_id}/{idx}    ← store chunk
 *   GET  /retrieve/{file_id}/{idx} ← retrieve chunk
 *   GET  /delete/{file_id}/{idx}   ← delete chunk
 *
 * STREAMING WRITE:
 *   Instead of buffering entire chunk in RAM,
 *   we stream directly to disk as data arrives.
 *   This halves memory usage and removes the
 *   copy-then-write bottleneck.
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    FILE *fp;          /* direct-to-disk stream    */
    size_t total;      /* bytes written so far     */
    char path[4096];   /* final file path          */
    int error;         /* write error flag         */
} SubConn;

enum MHD_Result subserver_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    (void)cls; (void)version;

    /* ═══════════════════════════════════════════
       GET /ping — circuit warmup probe
       ═══════════════════════════════════════════ */

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

    /* ═══════════════════════════════════════════
       GET /health or /
       ═══════════════════════════════════════════ */

    if (strcmp(method, "GET") == 0 &&
        (strcmp(url, "/health") == 0 ||
         strcmp(url, "/") == 0)) {

        const char *ok = "OK\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(ok), (void *)ok,
                MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(r,
            "Content-Type", "text/plain");
        enum MHD_Result rv =
            MHD_queue_response(conn,
                MHD_HTTP_OK, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* ═══════════════════════════════════════════
       POST /store/{file_id}/{chunk_idx}
       
       STREAMING: Open file on first call,
       write data as it arrives, close on
       final call (upload_data_size == 0).
       
       No intermediate RAM buffer needed.
       ═══════════════════════════════════════════ */

    if (strcmp(method, "POST") == 0 &&
        strncmp(url, "/store/", 7) == 0) {

        /* First call — create connection state
           and open output file */
                if (!*con_cls) {
            char fid[128] = {0};
            uint32_t cidx = 0;

            if (sscanf(url, "/store/%64[^/]/%u", fid, &cidx) != 2 ||
                validate_file_id(fid) != 0 ||
                cidx > 999999) {

                const char *e = "Bad URL\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv = MHD_queue_response(conn, 400, r);
                MHD_destroy_response(r);
                return rv;
            }

            char dir[4096];
            chunk_dir_path(dir, sizeof(dir), fid);
            mkdir_p(dir, 0700);

            SubConn *sc = calloc(1, sizeof(SubConn));
            chunk_file_path(sc->path, sizeof(sc->path), fid, cidx);

            sc->fp = fopen(sc->path, "wb");
            if (!sc->fp) {
                free(sc);
                const char *e = "Cannot create file\n";
                struct MHD_Response *r =
                    MHD_create_response_from_buffer(
                        strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
                enum MHD_Result rv = MHD_queue_response(conn, 500, r);
                MHD_destroy_response(r);
                return rv;
            }

            sc->total = 0;
            sc->error = 0;
            *con_cls = sc;
            return MHD_YES;
        }

        SubConn *sc = *con_cls;

        /* Data arriving — write directly
           to disk */
        if (*upload_data_size > 0) {
            if (!sc->error && sc->fp) {
                if (sc->total + *upload_data_size > (size_t)64 * 1024 * 1024) {
                    sc->error = 1;
                } else {
                    size_t w = fwrite(
                        upload_data, 1,
                        *upload_data_size,
                        sc->fp);

                    if (w != *upload_data_size) {
                        sc->error = 1;
                    }

                    sc->total += w;
                }
            }

            *upload_data_size = 0;
            return MHD_YES;
        }

        /* Final call — close file and respond */
        if (sc->fp) {
            fflush(sc->fp);
            fclose(sc->fp);
            sc->fp = NULL;
        }

        enum MHD_Result rv;

        if (sc->error) {
            /* Write failed — delete partial */
            unlink(sc->path);

            const char *e = "Write error\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            rv = MHD_queue_response(
                conn, 500, r);
            MHD_destroy_response(r);
        } else {
            const char *ok = "OK\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(ok), (void *)ok,
                    MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(r,
                "Connection", "keep-alive");
            rv = MHD_queue_response(
                conn, 200, r);
            MHD_destroy_response(r);
        }

        free(sc);
        *con_cls = NULL;
        return rv;
    }

    /* ═══════════════════════════════════════════
       GET /retrieve/{file_id}/{chunk_idx}
       
       Uses sendfile-style response via
       MHD_create_response_from_fd for
       zero-copy where possible.
       ═══════════════════════════════════════════ */

    if (strcmp(method, "GET") == 0 &&
        strncmp(url, "/retrieve/", 10) == 0) {

        char fid[128];
        uint32_t cidx = 0;

        if (sscanf(url, "/retrieve/%64[^/]/%u", fid, &cidx) != 2 ||
            validate_file_id(fid) != 0 ||
            cidx > 999999) {

            const char *e = "Bad URL\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e, MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv = MHD_queue_response(conn, 400, r);
            MHD_destroy_response(r);
            return rv;
        }

        
        char path[4096];
        chunk_file_path(path, sizeof(path),
                        fid, cidx);

        /* Use file descriptor for zero-copy */
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            const char *nf = "Not found\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(nf), (void *)nf,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 404, r);
            MHD_destroy_response(r);
            return rv;
        }

        struct stat st;
        if (fstat(fd, &st) != 0 ||
            st.st_size <= 0) {
            close(fd);
            const char *e = "Empty chunk\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(
                    conn, 404, r);
            MHD_destroy_response(r);
            return rv;
        }

        /* Zero-copy: MHD reads directly
           from fd, no malloc needed */
        struct MHD_Response *r =
            MHD_create_response_from_fd(
                (uint64_t)st.st_size, fd);
        /* fd is closed by MHD after response */

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

    /* ═══════════════════════════════════════════
       GET /delete/{file_id}/{chunk_idx}
       ═══════════════════════════════════════════ */

        if (strcmp(method, "GET") == 0 &&
        strncmp(url, "/delete/", 8) == 0) {

        const char *denied = "Forbidden\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(denied), (void *)denied, MHD_RESPMEM_PERSISTENT);
        enum MHD_Result rv = MHD_queue_response(conn, 403, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* ═══════════════════════════════════════════
       404 — unknown endpoint
       ═══════════════════════════════════════════ */

    const char *nf = "Not Found\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf,
            MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn, 404, r);
}

/* ──────────────────────────────────────────────────────────────
 * START SINGLE SUB-SERVER
 *
 * FIX: MHD_USE_THREAD_PER_CONNECTION allows
 * multiple chunks to be stored/retrieved
 * simultaneously on one sub-server.
 *
 * Previous code used single-threaded polling
 * which serialized all requests.
 * ────────────────────────────────────────────────────────────── */

int storage_start_subserver(int index,
                            int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);

    if (index < 0 ||
        index >= app.num_sub_servers) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return -1;
    }

    SubServer *ss = &app.sub_servers[index];

    if (ss->active) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return 0;
    }

    /*
     * MHD_USE_THREAD_PER_CONNECTION:
     *   Each incoming request gets its own
     *   thread. This means chunk 0 and chunk 3
     *   can be written to disk simultaneously
     *   on the same sub-server.
     *
     * MHD_OPTION_CONNECTION_LIMIT:
     *   Cap concurrent connections to prevent
     *   resource exhaustion.
     *
     * MHD_OPTION_CONNECTION_TIMEOUT:
     *   Close idle connections after 30s to
     *   free threads.
     *
     * Previous code:
     *   MHD_USE_INTERNAL_POLLING_THREAD
     *   = single thread, all requests serial
     *
     * After fix:
     *   MHD_USE_THREAD_PER_CONNECTION
     *   = parallel request handling
     */

    struct sockaddr_in sub_bind;
    memset(&sub_bind, 0, sizeof(sub_bind));
    sub_bind.sin_family = AF_INET;
    sub_bind.sin_port = htons((uint16_t)ss->port);
    sub_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ss->daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_THREAD_PER_CONNECTION |
        MHD_USE_ERROR_LOG,
        (uint16_t)ss->port,
        NULL, NULL,
        &subserver_handler, NULL,
        MHD_OPTION_CONNECTION_LIMIT,
        (unsigned int)MHD_CONN_LIMIT,
        MHD_OPTION_CONNECTION_TIMEOUT,
        (unsigned int)30,
        MHD_OPTION_SOCK_ADDR,
        (struct sockaddr *)&sub_bind,
        MHD_OPTION_END);

    if (!ss->daemon) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        gui_post_log(log_target,
            "Sub-server #%d failed on "
            "port %d: %s",
            index, ss->port,
            strerror(errno));
        return -1;
    }

    ss->active = 1;
    pthread_mutex_unlock(&app.subserver_mutex);

    if (index < 3 || index % 50 == 0)
        gui_post_log(log_target,
            "Sub-server #%d on port %d "
            "(multi-threaded)",
            index, ss->port);

    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * START ALL SUB-SERVERS
 * ────────────────────────────────────────────────────────────── */

void storage_start_all_subservers(int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);
    int n = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    int started = 0;
    int failed = 0;

    for (int i = 0; i < n; i++) {
        if (storage_start_subserver(i,
                log_target) == 0)
            started++;
        else
            failed++;
    }

    gui_post_log(log_target,
        "Sub-servers: %d started "
        "(multi-threaded), %d failed, "
        "port range %d–%d",
        started, failed,
        SUB_PORT_BASE,
        SUB_PORT_BASE + n - 1);
}

/* ──────────────────────────────────────────────────────────────
 * STOP ALL SUB-SERVERS
 * ────────────────────────────────────────────────────────────── */

void storage_stop_subservers(void)
{
    pthread_mutex_lock(&app.subserver_mutex);

    for (int i = 0;
         i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].daemon) {
            MHD_stop_daemon(
                app.sub_servers[i].daemon);
            app.sub_servers[i].daemon = NULL;
            app.sub_servers[i].active = 0;
        }
    }

    pthread_mutex_unlock(&app.subserver_mutex);
}

/* ──────────────────────────────────────────────────────────────
 * ADD SINGLE SUB-SERVER
 * ────────────────────────────────────────────────────────────── */

int storage_add_subserver(const char *address,
                          int port,
                          int log_target)
{
    if (port < SUB_PORT_BASE ||
        port > SUB_PORT_MAX) {
        gui_post_log(log_target,
            "Port %d out of range [%d–%d]",
            port, SUB_PORT_BASE, SUB_PORT_MAX);
        return -1;
    }

    pthread_mutex_lock(&app.subserver_mutex);

    if (app.num_sub_servers >= MAX_SUB_SERVERS) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        gui_post_log(log_target,
            "Max sub-servers reached (%d)",
            MAX_SUB_SERVERS);
        return -1;
    }

    if (ensure_subserver_capacity() != 0) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        gui_post_log(log_target,
            "Memory allocation failed");
        return -1;
    }

    for (int i = 0;
         i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].port == port) {
            pthread_mutex_unlock(
                &app.subserver_mutex);
            gui_post_log(log_target,
                "Port %d already in use",
                port);
            return -1;
        }
    }

    SubServer *ss =
        &app.sub_servers[app.num_sub_servers];
    memset(ss, 0, sizeof(*ss));
    strncpy(ss->address, address,
            sizeof(ss->address) - 1);
    ss->port   = port;
    ss->active = 0;
    ss->daemon = NULL;

    int idx = app.num_sub_servers;
    app.num_sub_servers++;

    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "Added sub-server #%d: %s:%d",
        idx, address, port);
    return idx;
}

/* ──────────────────────────────────────────────────────────────
 * BATCH ADD SUB-SERVERS
 * ────────────────────────────────────────────────────────────── */

int storage_add_subservers_batch(int count,
                                 int log_target)
{
    if (count <= 0) return 0;
    if (count > MAX_SUB_SERVERS)
        count = MAX_SUB_SERVERS;

    int added = 0;
    int next_port = SUB_PORT_BASE;

    pthread_mutex_lock(&app.subserver_mutex);
    for (int i = 0;
         i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].port >= next_port)
            next_port =
                app.sub_servers[i].port + 1;
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "Adding %d sub-servers starting "
        "at port %d...", count, next_port);

    for (int i = 0;
         i < count && next_port <= SUB_PORT_MAX;
         i++) {

        int duplicate = 0;
        pthread_mutex_lock(&app.subserver_mutex);
        for (int j = 0;
             j < app.num_sub_servers; j++) {
            if (app.sub_servers[j].port ==
                next_port) {
                duplicate = 1;
                break;
            }
        }
        pthread_mutex_unlock(
            &app.subserver_mutex);

        if (duplicate) {
            next_port++;
            i--;
            continue;
        }

        int idx = storage_add_subserver(
            "127.0.0.1", next_port, log_target);

        if (idx >= 0) {
            storage_start_subserver(idx,
                                    log_target);
            added++;
        }

        next_port++;

        if (added > 0 && added % 50 == 0) {
            gui_post_log(log_target,
                "  ...%d/%d sub-servers started",
                added, count);
        }
    }

    gui_post_log(log_target,
        "Batch complete: %d sub-servers "
        "active (multi-threaded, "
        "ports %d–%d)",
        added, SUB_PORT_BASE,
        SUB_PORT_BASE + added - 1);

    return added;
}

/* ──────────────────────────────────────────────────────────────
 * ACTIVE COUNT
 * ────────────────────────────────────────────────────────────── */

int storage_active_subserver_count(void)
{
    int count = 0;
    pthread_mutex_lock(&app.subserver_mutex);

    for (int i = 0;
         i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].active)
            count++;
    }

    pthread_mutex_unlock(&app.subserver_mutex);
    return count;
}