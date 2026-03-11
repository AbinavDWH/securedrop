#include "storage.h"
#include "crypto.h"
#include "gui_helpers.h"

#include <dirent.h>
#include <curl/curl.h>

/* ──────────────────────────────────────────────────────────────
 * INITIALIZATION
 * ────────────────────────────────────────────────────────────── */

void storage_init(void)
{
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
}

/* ── Grow sub-server array if needed ───────────────────────── */

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
           (size_t)(new_cap - app.sub_servers_cap) *
           sizeof(SubServer));

    app.sub_servers = new_arr;
    app.sub_servers_cap = new_cap;
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * CHUNK PATH HELPERS
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
 * CURL WRITE CALLBACK
 * ────────────────────────────────────────────────────────────── */

typedef struct { Buf *buf; } CurlBufCtx;

static size_t curl_write_buf(void *data, size_t size,
                             size_t nmemb, void *userp)
{
    CurlBufCtx *ctx = userp;
    size_t total = size * nmemb;
    buf_add(ctx->buf, data, total);
    return total;
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
 * STORE CHUNK
 * ────────────────────────────────────────────────────────────── */

int storage_store_chunk(const char *file_id,
                        uint32_t chunk_idx,
                        const unsigned char *data,
                        size_t len,
                        int log_target)
{
    int sub_idx = -1;

    pthread_mutex_lock(&app.subserver_mutex);

    if (app.num_sub_servers > 0) {
        int best = -1;
        int min_chunks = INT32_MAX;

        for (int i = 0;
             i < app.num_sub_servers; i++) {
            if (app.sub_servers[i].active &&
                app.sub_servers[i].chunk_count <
                    min_chunks) {
                min_chunks =
                    app.sub_servers[i].chunk_count;
                best = i;
            }
        }

        if (best >= 0) {
            SubServer *ss = &app.sub_servers[best];
            char url[512];
            snprintf(url, sizeof(url),
                "http://%s:%d/store/%s/%u",
                ss->address, ss->port,
                file_id, chunk_idx);

            pthread_mutex_unlock(
                &app.subserver_mutex);

            CURL *c = curl_easy_init();
            if (c) {
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
                    CURLOPT_TIMEOUT, 30L);
                curl_easy_setopt(c,
                    CURLOPT_CONNECTTIMEOUT, 5L);

                CURLcode res =
                    curl_easy_perform(c);
                curl_slist_free_all(hdr);
                curl_easy_cleanup(c);

                if (res == CURLE_OK) {
                    pthread_mutex_lock(
                        &app.subserver_mutex);
                    ss->chunk_count++;
                    sub_idx = best;
                    pthread_mutex_unlock(
                        &app.subserver_mutex);
                    return sub_idx;
                }
            }

            pthread_mutex_lock(
                &app.subserver_mutex);
        }
    }

    pthread_mutex_unlock(&app.subserver_mutex);

    /* Local fallback */
    char dir[4096];
    chunk_dir_path(dir, sizeof(dir), file_id);
    mkdir_p(dir, 0700);

    char path[4096];
    chunk_file_path(path, sizeof(path),
                    file_id, chunk_idx);

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    fwrite(data, 1, len, fp);
    fclose(fp);

    return -1;
}

/* ──────────────────────────────────────────────────────────────
 * RETRIEVE CHUNK
 * ────────────────────────────────────────────────────────────── */

int storage_retrieve_chunk(const char *file_id,
                           uint32_t chunk_idx,
                           int sub_server_idx,
                           Buf *out,
                           int log_target)
{
    if (sub_server_idx >= 0) {
        pthread_mutex_lock(&app.subserver_mutex);

        if (sub_server_idx < app.num_sub_servers &&
            app.sub_servers[sub_server_idx].active) {

            SubServer *ss =
                &app.sub_servers[sub_server_idx];
            char url[512];
            snprintf(url, sizeof(url),
                "http://%s:%d/retrieve/%s/%u",
                ss->address, ss->port,
                file_id, chunk_idx);

            pthread_mutex_unlock(
                &app.subserver_mutex);

            CURL *c = curl_easy_init();
            if (c) {
                CurlBufCtx ctx = { .buf = out };
                curl_easy_setopt(c,
                    CURLOPT_URL, url);
                curl_easy_setopt(c,
                    CURLOPT_WRITEFUNCTION,
                    curl_write_buf);
                curl_easy_setopt(c,
                    CURLOPT_WRITEDATA, &ctx);
                curl_easy_setopt(c,
                    CURLOPT_TIMEOUT, 30L);

                CURLcode res =
                    curl_easy_perform(c);
                curl_easy_cleanup(c);

                if (res == CURLE_OK &&
                    out->len > 0)
                    return 0;
            }
        } else {
            pthread_mutex_unlock(
                &app.subserver_mutex);
        }
    }

    /* Local fallback */
    char path[4096];
    chunk_file_path(path, sizeof(path),
                    file_id, chunk_idx);

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(fp); return -1; }

    fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

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

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    fwrite(meta, sizeof(StoredFileMeta), 1, fp);
    fclose(fp);
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

    char mp[4096];
    meta_file_path(mp, sizeof(mp), file_id);
    unlink(mp);

    pthread_mutex_lock(&app.stored_mutex);
    for (int i = 0;
         i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id) == 0) {
            memmove(&app.stored_files[i],
                &app.stored_files[i + 1],
                (size_t)(app.stored_file_count -
                         i - 1) *
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
 * SUB-SERVER: ADD SINGLE
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
                "Port %d already in use", port);
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
 * SUB-SERVER: BATCH ADD
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
        "Batch complete: %d sub-servers active "
        "(ports %d–%d)",
        added, SUB_PORT_BASE,
        SUB_PORT_BASE + added - 1);

    return added;
}

/* ──────────────────────────────────────────────────────────────
 * SUB-SERVER HTTP HANDLER
 *
 * Endpoints:
 *   GET  /ping                    ← circuit warmup
 *   GET  /health  or  /           ← health check
 *   POST /store/{file_id}/{idx}   ← store chunk
 *   GET  /retrieve/{file_id}/{idx}← retrieve chunk
 * ────────────────────────────────────────────────────────────── */

typedef struct { Buf buf; } SubConn;

enum MHD_Result subserver_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version, const char *upload_data,
    size_t *upload_data_size, void **con_cls)
{
    (void)cls; (void)version;

    /* ════════════════════════════════════════════
       GET /ping — circuit warmup probe
       
       Client calls this BEFORE real chunk
       transfers to pre-establish the Tor
       circuit through each independent
       .onion address.
       
       First .onion contact needs:
         1. 3-hop circuit to introduction point
         2. Rendezvous negotiation  
         3. 3-hop circuit to rendezvous point
       = 6 Tor hops, 10-60 seconds cold
       
       After warmup the circuit is cached
       and subsequent requests are fast.
       ════════════════════════════════════════════ */

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

    /* ════════════════════════════════════════════
       GET /health or / — health check
       ════════════════════════════════════════════ */

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

    /* ════════════════════════════════════════════
       POST /store/{file_id}/{chunk_idx}
       ════════════════════════════════════════════ */

    if (strcmp(method, "POST") == 0 &&
        strncmp(url, "/store/", 7) == 0) {

        if (!*con_cls) {
            SubConn *sc =
                calloc(1, sizeof(SubConn));
            buf_init(&sc->buf);
            *con_cls = sc;
            return MHD_YES;
        }

        SubConn *sc = *con_cls;
        if (*upload_data_size > 0) {
            buf_add(&sc->buf, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        char fid[128];
        uint32_t cidx = 0;
        if (sscanf(url, "/store/%127[^/]/%u",
                   fid, &cidx) != 2) {
            const char *e = "Bad URL\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            enum MHD_Result rv =
                MHD_queue_response(conn, 400, r);
            MHD_destroy_response(r);
            buf_free(&sc->buf);
            free(sc);
            *con_cls = NULL;
            return rv;
        }

        char dir[4096];
        chunk_dir_path(dir, sizeof(dir), fid);
        mkdir_p(dir, 0700);

        char path[4096];
        chunk_file_path(path, sizeof(path),
                        fid, cidx);

        FILE *fp = fopen(path, "wb");
        if (fp) {
            fwrite(sc->buf.data, 1,
                   sc->buf.len, fp);
            fclose(fp);
        }

        const char *ok = "OK\n";
        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                strlen(ok), (void *)ok,
                MHD_RESPMEM_PERSISTENT);
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        buf_free(&sc->buf);
        free(sc);
        *con_cls = NULL;
        return rv;
    }

    /* ════════════════════════════════════════════
       GET /retrieve/{file_id}/{chunk_idx}
       ════════════════════════════════════════════ */

    if (strcmp(method, "GET") == 0 &&
        strncmp(url, "/retrieve/", 10) == 0) {

        char fid[128];
        uint32_t cidx = 0;
        if (sscanf(url, "/retrieve/%127[^/]/%u",
                   fid, &cidx) != 2) {
            const char *e = "Bad URL\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(e), (void *)e,
                    MHD_RESPMEM_PERSISTENT);
            return MHD_queue_response(
                conn, 400, r);
        }

        char path[4096];
        chunk_file_path(path, sizeof(path),
                        fid, cidx);

        FILE *fp = fopen(path, "rb");
        if (!fp) {
            const char *nf = "Not found\n";
            struct MHD_Response *r =
                MHD_create_response_from_buffer(
                    strlen(nf), (void *)nf,
                    MHD_RESPMEM_PERSISTENT);
            return MHD_queue_response(
                conn, 404, r);
        }

        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        unsigned char *data = malloc((size_t)sz);
        fread(data, 1, (size_t)sz, fp);
        fclose(fp);

        struct MHD_Response *r =
            MHD_create_response_from_buffer(
                (size_t)sz, data,
                MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(r,
            "Content-Type",
            "application/octet-stream");
        enum MHD_Result rv =
            MHD_queue_response(conn, 200, r);
        MHD_destroy_response(r);
        return rv;
    }

    /* ════════════════════════════════════════════
       404 — unknown endpoint
       ════════════════════════════════════════════ */

    const char *nf = "Not Found\n";
    struct MHD_Response *r =
        MHD_create_response_from_buffer(
            strlen(nf), (void *)nf,
            MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn, 404, r);
}

/* ──────────────────────────────────────────────────────────────
 * START SINGLE SUB-SERVER
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

    ss->daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD |
        MHD_USE_ERROR_LOG,
        (uint16_t)ss->port,
        NULL, NULL,
        &subserver_handler, NULL,
        MHD_OPTION_END);

    if (!ss->daemon) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        gui_post_log(log_target,
            "Sub-server #%d failed on port %d",
            index, ss->port);
        return -1;
    }

    ss->active = 1;
    pthread_mutex_unlock(&app.subserver_mutex);

    if (index < 3 || index % 50 == 0)
        gui_post_log(log_target,
            "Sub-server #%d on port %d",
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
        "Sub-servers: %d started, %d failed, "
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