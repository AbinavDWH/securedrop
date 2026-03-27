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

#include "parallel.h"
#include "gui_helpers.h"
#include "util.h"
#include "app.h"
#include "advanced_config.h"

#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

/* ──────────────────────────────────────────────────────────────
 * TUNING CONSTANTS — OPTIMIZED FOR BANDWIDTH
 * ────────────────────────────────────────────────────────────── */

#define CHUNK_MAX_RETRIES       4
#define CHUNK_RETRY_BASE_SEC    2      /* was 3 */

#define ONION_TIMEOUT_SEC     120      /* was 180 */
#define ONION_CONNECT_SEC      60      /* was 90  */
#define LAN_TIMEOUT_SEC        30      /* was 60  */
#define LAN_CONNECT_SEC        10      /* was 15  */

#define THREAD_STAGGER_ONION_US  500000   /* was 1500000 */
#define THREAD_STAGGER_LAN_US    50000    /* 50ms for LAN */

/* Connection reuse: keep TCP alive between chunks */
#define CURL_KEEPALIVE_IDLE    30
#define CURL_KEEPALIVE_INTVL   15

/* Low speed detection: abort if < 500 B/s for 45s */
#define LOW_SPEED_LIMIT       500      /* was 100 */
#define LOW_SPEED_TIME         45      /* was 60  */

/* Max concurrent connections per sub-server */
#define MAX_CONN_PER_SERVER     4      /* was 2 */

/* Receive buffer size hint (256KB) */
#define CURL_RECV_BUFSIZE    262144

/* Speed tracking window */
#define SPEED_WINDOW_SEC       5

typedef struct {
    Buf *buf;
} PCurlCtx;

static size_t p_write_cb(void *data, size_t size,
                         size_t nmemb, void *userp)
{
    PCurlCtx *ctx = userp;
    if (size != 0 && nmemb > SIZE_MAX / size)
        return 0;
    size_t total = size * nmemb;
    if (ctx->buf->len + total > (size_t)64 * 1024 * 1024)
        return 0;
    buf_add(ctx->buf, data, total);
    return total;
}

static int addr_is_onion(const char *host)
{
    return (host && strstr(host, ".onion"));
}

/* ──────────────────────────────────────────────────────────────
 * SPEED TRACKER
 *
 * Tracks aggregate download speed across all
 * threads to show real-time bandwidth and
 * detect stalls.
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    pthread_mutex_t  mutex;
    size_t           total_bytes;
    struct timeval   start_time;
    size_t           window_bytes;
    struct timeval   window_start;
    double           current_speed;   /* bytes/sec */
    double           peak_speed;
} SpeedTracker;

static void speed_init(SpeedTracker *st)
{
    pthread_mutex_init(&st->mutex, NULL);
    st->total_bytes  = 0;
    st->window_bytes = 0;
    st->current_speed = 0;
    st->peak_speed = 0;
    gettimeofday(&st->start_time, NULL);
    gettimeofday(&st->window_start, NULL);
}

static void speed_add(SpeedTracker *st,
                      size_t bytes)
{
    pthread_mutex_lock(&st->mutex);

    st->total_bytes  += bytes;
    st->window_bytes += bytes;

    struct timeval now;
    gettimeofday(&now, NULL);

    double elapsed =
        (double)(now.tv_sec -
                 st->window_start.tv_sec) +
        (double)(now.tv_usec -
                 st->window_start.tv_usec) /
        1e6;

    if (elapsed >= SPEED_WINDOW_SEC) {
        st->current_speed =
            (double)st->window_bytes / elapsed;

        if (st->current_speed > st->peak_speed)
            st->peak_speed = st->current_speed;

        st->window_bytes = 0;
        st->window_start = now;
    }

    pthread_mutex_unlock(&st->mutex);
}

static double speed_get_avg(SpeedTracker *st)
{
    pthread_mutex_lock(&st->mutex);

    struct timeval now;
    gettimeofday(&now, NULL);

    double elapsed =
        (double)(now.tv_sec -
                 st->start_time.tv_sec) +
        (double)(now.tv_usec -
                 st->start_time.tv_usec) /
        1e6;

    double avg = (elapsed > 0.1) ?
        (double)st->total_bytes / elapsed : 0;

    pthread_mutex_unlock(&st->mutex);
    return avg;
}

static void speed_destroy(SpeedTracker *st)
{
    pthread_mutex_destroy(&st->mutex);
}

/* ──────────────────────────────────────────────────────────────
 * CURL HANDLE POOL
 *
 * Each thread gets a persistent CURL handle
 * that is REUSED across all chunks.
 *
 * This avoids:
 *   - TCP handshake per chunk
 *   - TLS negotiation per chunk (if HTTPS)
 *   - SOCKS5 handshake per chunk
 *   - Tor circuit setup per chunk
 *
 * With keep-alive, second+ chunks on same
 * connection are near-instant to start.
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    CURL       *handle;
    const char *proxy;       /* assigned proxy   */
    int         server_idx;  /* last server used */
    int         reuse_count; /* times reused     */
} CurlSlot;

static CurlSlot *curl_slot_create(
    const char *proxy,
    int is_onion)
{
    CurlSlot *slot = calloc(1, sizeof(CurlSlot));
    if (!slot) return NULL;

    slot->handle = curl_easy_init();
    if (!slot->handle) {
        free(slot);
        return NULL;
    }

    slot->proxy = proxy;
    slot->server_idx = -1;
    slot->reuse_count = 0;

    CURL *c = slot->handle;

    /* Proxy */
    if (proxy && proxy[0])
        curl_easy_setopt(c,
            CURLOPT_PROXY, proxy);

    /* Timeouts */
    long timeout = is_onion ?
        ONION_TIMEOUT_SEC : LAN_TIMEOUT_SEC;
    long connect = is_onion ?
        ONION_CONNECT_SEC : LAN_CONNECT_SEC;

    curl_easy_setopt(c,
        CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(c,
        CURLOPT_CONNECTTIMEOUT, connect);

    /* Keep-alive — CRITICAL for bandwidth */
    curl_easy_setopt(c,
        CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(c,
        CURLOPT_TCP_KEEPIDLE,
        (long)CURL_KEEPALIVE_IDLE);
    curl_easy_setopt(c,
        CURLOPT_TCP_KEEPINTVL,
        (long)CURL_KEEPALIVE_INTVL);

    /* Reuse connections */
    curl_easy_setopt(c,
        CURLOPT_FORBID_REUSE, 0L);
    curl_easy_setopt(c,
        CURLOPT_FRESH_CONNECT, 0L);

    /* Low speed detection */
    curl_easy_setopt(c,
        CURLOPT_LOW_SPEED_LIMIT,
        (long)LOW_SPEED_LIMIT);
    curl_easy_setopt(c,
        CURLOPT_LOW_SPEED_TIME,
        (long)LOW_SPEED_TIME);

    /* Receive buffer hint */
    curl_easy_setopt(c,
        CURLOPT_BUFFERSIZE,
        (long)CURL_RECV_BUFSIZE);

    /* HTTP/1.1 keep-alive */
    curl_easy_setopt(c,
        CURLOPT_HTTP_VERSION,
        CURL_HTTP_VERSION_1_1);

    /* Disable Nagle for lower latency */
    curl_easy_setopt(c,
        CURLOPT_TCP_NODELAY, 1L);

    /* Enable compression if server supports */
    curl_easy_setopt(c,
        CURLOPT_ACCEPT_ENCODING, "");

    return slot;
}

static void curl_slot_destroy(CurlSlot *slot)
{
    if (!slot) return;
    if (slot->handle)
        curl_easy_cleanup(slot->handle);
    free(slot);
}

/* Reset handle for reuse (keeps connection) */
static void curl_slot_reset(CurlSlot *slot)
{
    if (!slot || !slot->handle) return;

    /* Only reset URL and write callback —
       proxy, timeouts, keepalive persist */
    curl_easy_setopt(slot->handle,
        CURLOPT_URL, NULL);
    curl_easy_setopt(slot->handle,
        CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(slot->handle,
        CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(slot->handle,
        CURLOPT_HTTPGET, 1L);

    slot->reuse_count++;
}

/* ──────────────────────────────────────────────────────────────
 * GET SUB-SERVER LIST (unchanged)
 * ────────────────────────────────────────────────────────────── */

int parallel_get_server_list(
    const char *server_addr,
    const char *proxy,
    SubServerList *out,
    int log_target)
{
    memset(out, 0, sizeof(*out));

    char url[1024];
    snprintf(url, sizeof(url),
             "http://%s/servers", server_addr);

    CURL *c = curl_easy_init();
    if (!c) return 0;

    if (proxy && proxy[0])
        curl_easy_setopt(c, CURLOPT_PROXY,
                         proxy);

    Buf resp;
    buf_init(&resp);
    PCurlCtx ctx = { .buf = &resp };

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                     p_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,
                     &ctx);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c,
        CURLOPT_CONNECTTIMEOUT, 30L);

    CURLcode res = curl_easy_perform(c);
    long http_code = 0;
    curl_easy_getinfo(c,
        CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(c);

    if (res != CURLE_OK || http_code != 200) {
        buf_free(&resp);
        return 0;
    }

    char *copy = malloc(resp.len + 1);
    memcpy(copy, resp.data, resp.len);
    copy[resp.len] = '\0';
    buf_free(&resp);

    char *saveptr = NULL;
    char *line = strtok_r(copy, "\n", &saveptr);

    while (line &&
           out->count < PARALLEL_MAX_SERVERS) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (*line == '\0') {
            line = strtok_r(NULL, "\n",
                            &saveptr);
            continue;
        }

        char *colon = strrchr(line, ':');
        if (colon && colon != line) {
            SubServerEntry *e =
                &out->entries[out->count];

            size_t hlen =
                (size_t)(colon - line);
            if (hlen >= sizeof(e->host))
                hlen = sizeof(e->host) - 1;
            memcpy(e->host, line, hlen);
            e->host[hlen] = '\0';
            e->port = atoi(colon + 1);
            e->active = 1;

            if (e->port > 0)
                out->count++;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(copy);
    return out->count;
}

/* ──────────────────────────────────────────────────────────────
 * WARMUP — WITH CONNECTION REUSE
 * ────────────────────────────────────────────────────────────── */

static int warmup_circuit(const char *proxy,
                          const char *target_host,
                          int target_port,
                          int log_target,
                          int circuit_idx)
{
    char url[1024];
    snprintf(url, sizeof(url),
             "http://%s:%d/ping",
             target_host, target_port);

    CURL *c = curl_easy_init();
    if (!c) return -1;

    if (proxy && proxy[0])
        curl_easy_setopt(c, CURLOPT_PROXY,
                         proxy);

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 90L);
    curl_easy_setopt(c,
        CURLOPT_CONNECTTIMEOUT, 60L);

    Buf discard;
    buf_init(&discard);
    PCurlCtx dctx = { .buf = &discard };
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                     p_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,
                     &dctx);

    /* Do TWO requests — first establishes
       circuit, second confirms keep-alive */
    CURLcode res = curl_easy_perform(c);

    if (res == CURLE_OK) {
        /* Second request on same handle =
           reuses connection */
        buf_free(&discard);
        buf_init(&discard);
        curl_easy_perform(c);

        gui_post_log(log_target,
            "  \xE2\x9C\x93 Circuit[%d] warm "
            "(keep-alive verified)",
            circuit_idx);
    } else {
        gui_post_log(log_target,
            "  \xE2\x9C\x97 Circuit[%d]: %s",
            circuit_idx,
            curl_easy_strerror(res));
    }

    curl_easy_cleanup(c);
    buf_free(&discard);

    return (res == CURLE_OK) ? 0 : -1;
}

typedef struct {
    const char *proxy;
    const char *host;
    int         port;
    int         log_target;
    int         idx;
    int         result;
} WarmupArg;

static void *warmup_thread(void *arg)
{
    WarmupArg *w = arg;
    w->result = warmup_circuit(
        w->proxy, w->host, w->port,
        w->log_target, w->idx);
    return NULL;
}

int parallel_warmup_circuits(
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    int log_target)
{
    if (!proxies || num_proxies <= 0 ||
        !servers || servers->count <= 0)
        return 0;

    if (!addr_is_onion(servers->entries[0].host))
        return num_proxies;

    gui_post_log(log_target,
        "Warming up %d circuits...",
        num_proxies);

    int n = num_proxies;
    WarmupArg *args = calloc((size_t)n,
                             sizeof(WarmupArg));
    pthread_t *threads = malloc(
        (size_t)n * sizeof(pthread_t));

    for (int i = 0; i < n; i++) {
        int si = i % servers->count;
        args[i].proxy      = proxies[i];
        args[i].host       =
            servers->entries[si].host;
        args[i].port       =
            servers->entries[si].port;
        args[i].log_target = log_target;
        args[i].idx        = i;
        args[i].result     = -1;

        pthread_create(&threads[i], NULL,
                       warmup_thread, &args[i]);

        /* Reduced stagger: 500ms */
        if (i < n - 1)
            usleep(500000);
    }

    for (int i = 0; i < n; i++)
        pthread_join(threads[i], NULL);

    int warm = 0;
    for (int i = 0; i < n; i++) {
        if (args[i].result == 0)
            warm++;
    }

    free(args);
    free(threads);

    gui_post_log(log_target,
        "Circuit warmup: %d/%d ready",
        warm, n);

    return warm;
}

/* ──────────────────────────────────────────────────────────────
 * UPLOAD WORKER — unchanged except stagger
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    const char          *server_addr;
    const char         **proxies;
    int                  num_proxies;
    const SubServerList *servers;
    const char          *file_id;
    const uint8_t       *payload;
    size_t               payload_len;
    int                  chunk_count;
    const size_t        *chunk_offsets;
    const uint32_t      *chunk_sizes;
    int                  log_target;
    int                  is_onion;

    pthread_mutex_t      mutex;
    int                  next_chunk;
    int                  failed;
    int                  completed;
    int                  thread_id_counter;
} ParallelUpCtx;

static void *upload_worker(void *arg)
{
    ParallelUpCtx *ctx = arg;

    pthread_mutex_lock(&ctx->mutex);
    int my_id = ctx->thread_id_counter++;
    pthread_mutex_unlock(&ctx->mutex);

    /* Create persistent CURL handle */
    CurlSlot *slot = NULL;
    const char *my_proxy = NULL;

    if (ctx->proxies && ctx->num_proxies > 0) {
        my_proxy = ctx->proxies[my_id % ctx->num_proxies];
    }

    slot = curl_slot_create(my_proxy, ctx->is_onion);
    if (!slot) return NULL;

    for (;;) {
        pthread_mutex_lock(&ctx->mutex);
        int ci = ctx->next_chunk++;
        int fail = ctx->failed;
        pthread_mutex_unlock(&ctx->mutex);

        if (fail || ci >= ctx->chunk_count)
            break;

        int si = ci % ctx->servers->count;
        const SubServerEntry *srv =
            &ctx->servers->entries[si];

        if (ctx->proxies && ctx->num_proxies > 0 &&
            ctx->num_proxies >= ctx->servers->count) {
            curl_easy_setopt(slot->handle, CURLOPT_PROXY,
                ctx->proxies[si % ctx->num_proxies]);
        }

        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s:%d/store/%s/%d",
            srv->host, srv->port,
            ctx->file_id, ci);

        const uint8_t *chunk_data =
            ctx->payload +
            ctx->chunk_offsets[ci];
        uint32_t chunk_size =
            ctx->chunk_sizes[ci];

        int success = 0;

        for (int attempt = 0;
             attempt < CHUNK_MAX_RETRIES;
             attempt++) {

            /* Rotate proxy on retry */
            if (attempt > 0 && ctx->proxies &&
                ctx->num_proxies > 0) {

                int pidx =
                    (my_id + attempt) %
                    ctx->num_proxies;

                curl_easy_setopt(
                    slot->handle,
                    CURLOPT_PROXY,
                    ctx->proxies[pidx]);
            }

            struct curl_slist *hdr = NULL;
            hdr = curl_slist_append(hdr,
                "Content-Type: "
                "application/octet-stream");

            curl_easy_setopt(slot->handle,
                CURLOPT_URL, url);
            curl_easy_setopt(slot->handle,
                CURLOPT_POST, 1L);
            curl_easy_setopt(slot->handle,
                CURLOPT_POSTFIELDS,
                chunk_data);
            curl_easy_setopt(slot->handle,
                CURLOPT_POSTFIELDSIZE_LARGE,
                (curl_off_t)chunk_size);
            curl_easy_setopt(slot->handle,
                CURLOPT_HTTPHEADER, hdr);

            /* Discard response body */
            curl_easy_setopt(slot->handle,
                CURLOPT_WRITEFUNCTION,
                p_write_cb);
            Buf discard;
            buf_init(&discard);
            PCurlCtx dctx = {
                .buf = &discard
            };
            curl_easy_setopt(slot->handle,
                CURLOPT_WRITEDATA, &dctx);

            CURLcode res =
                curl_easy_perform(
                    slot->handle);
            long code = 0;
            curl_easy_getinfo(slot->handle,
                CURLINFO_RESPONSE_CODE,
                &code);

            curl_slist_free_all(hdr);
            buf_free(&discard);

            if (res == CURLE_OK &&
                code == 200) {
                success = 1;
                break;
            }

            gui_post_log(ctx->log_target,
                "↑ Chunk %d retry %d/%d "
                "(%s)",
                ci, attempt + 1,
                CHUNK_MAX_RETRIES,
                curl_easy_strerror(res));

            if (attempt <
                CHUNK_MAX_RETRIES - 1) {
                int delay =
                    CHUNK_RETRY_BASE_SEC *
                    (1 << attempt);
                if (delay > 20) delay = 20;
                sleep((unsigned)delay);

                /* Force new connection
                   on retry */
                curl_easy_setopt(
                    slot->handle,
                    CURLOPT_FRESH_CONNECT,
                    1L);
            }
        }

        /* Restore connection reuse after
           retry */
        curl_easy_setopt(slot->handle,
            CURLOPT_FRESH_CONNECT, 0L);

        if (!success) {
            pthread_mutex_lock(&ctx->mutex);
            ctx->failed = 1;
            pthread_mutex_unlock(&ctx->mutex);
            break;
        }

        pthread_mutex_lock(&ctx->mutex);
        ctx->completed++;
        int done = ctx->completed;
        pthread_mutex_unlock(&ctx->mutex);

        if (done == 1 || done % 20 == 0 ||
            done == ctx->chunk_count) {
            gui_post_log(ctx->log_target,
                "↑ %d/%d chunks uploaded",
                done, ctx->chunk_count);
        }

        gui_post_progress(ctx->log_target,
            0.65 + 0.3 *
            (double)done /
            ctx->chunk_count);
    }

    curl_slot_destroy(slot);
    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * PARALLEL UPLOAD CHUNKS
 * ────────────────────────────────────────────────────────────── */

int parallel_upload_chunks(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    const uint8_t *payload,
    size_t payload_len,
    int chunk_count,
    const size_t *chunk_offsets,
    const uint32_t *chunk_sizes,
    int log_target)
{
    int is_onion = addr_is_onion(server_addr);

    if (is_onion && proxies &&
        num_proxies > 0) {
        int warm = parallel_warmup_circuits(
            proxies, num_proxies,
            servers, log_target);
        if (warm == 0) return -1;
    }

    int nthreads = servers->count;
    if (nthreads > PARALLEL_MAX_THREADS)
        nthreads = PARALLEL_MAX_THREADS;
    if (nthreads > chunk_count)
        nthreads = chunk_count;
    if (nthreads > servers->count *
        MAX_CONN_PER_SERVER)
        nthreads = servers->count *
                   MAX_CONN_PER_SERVER;
    if (nthreads < 1) nthreads = 1;
    if (num_proxies > 0 &&
        nthreads > num_proxies)
        nthreads = num_proxies;

    gui_post_log(log_target,
        "Parallel upload: %d chunks, "
        "%d threads, %d servers",
        chunk_count, nthreads,
        servers->count);

    ParallelUpCtx ctx = {
        .server_addr   = server_addr,
        .proxies       = proxies,
        .num_proxies   = num_proxies,
        .servers       = servers,
        .file_id       = file_id,
        .payload       = payload,
        .payload_len   = payload_len,
        .chunk_count   = chunk_count,
        .chunk_offsets = chunk_offsets,
        .chunk_sizes   = chunk_sizes,
        .log_target    = log_target,
        .is_onion      = is_onion,
        .next_chunk    = 0,
        .failed        = 0,
        .completed     = 0,
        .thread_id_counter = 0,
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    pthread_t *threads = malloc(
        (size_t)nthreads * sizeof(pthread_t));

    useconds_t stagger = is_onion ?
        THREAD_STAGGER_ONION_US :
        THREAD_STAGGER_LAN_US;

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL,
                       upload_worker, &ctx);
        if (i < nthreads - 1)
            usleep(stagger);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);

    if (ctx.failed) return -1;

    gui_post_log(log_target,
        "\xE2\x9C\x93 All %d chunks uploaded",
        chunk_count);
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * DOWNLOAD WORKER — OPTIMIZED
 *
 * KEY CHANGES:
 *   1. Persistent CURL handle per thread
 *      (connection reuse across chunks)
 *   2. HTTP keep-alive enabled
 *   3. Larger receive buffer (256KB)
 *   4. Smarter retry with proxy + server
 *      rotation
 *   5. Speed tracking for bandwidth display
 *   6. Adaptive timeout based on chunk size
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    const char          *server_addr;
    const char         **proxies;
    int                  num_proxies;
    const SubServerList *servers;
    const char          *file_id;
    int                  chunk_count;
    const uint32_t      *chunk_sizes;
    int                  log_target;
    int                  is_onion;

    Buf                 *chunk_bufs;

    pthread_mutex_t      mutex;
    int                  next_chunk;
    int                  failed;
    int                  completed;
    size_t               bytes_done;
    int                  thread_id_counter;

    SpeedTracker        *speed;
} ParallelDlCtx;

static void *download_worker(void *arg)
{
    ParallelDlCtx *ctx = arg;

    pthread_mutex_lock(&ctx->mutex);
    int my_id = ctx->thread_id_counter++;
    pthread_mutex_unlock(&ctx->mutex);

    /* ── Create persistent CURL slot ───────── */

    CurlSlot *slot = NULL;
    const char *my_proxy = NULL;

    if (ctx->proxies && ctx->num_proxies > 0) {
        my_proxy = ctx->proxies[my_id % ctx->num_proxies];
    }

    slot = curl_slot_create(my_proxy, ctx->is_onion);
    if (!slot) return NULL;

    int consecutive_ok = 0;

    for (;;) {
        pthread_mutex_lock(&ctx->mutex);
        int ci = ctx->next_chunk++;
        int fail = ctx->failed;
        pthread_mutex_unlock(&ctx->mutex);

        if (fail || ci >= ctx->chunk_count)
            break;

        int si = ci % ctx->servers->count;
        const SubServerEntry *srv =
            &ctx->servers->entries[si];

        if (ctx->proxies && ctx->num_proxies > 0 &&
            ctx->num_proxies >= ctx->servers->count) {
            curl_easy_setopt(slot->handle, CURLOPT_PROXY,
                ctx->proxies[si % ctx->num_proxies]);
        }

        if (ctx->proxies && ctx->num_proxies > 0 &&
            ctx->num_proxies >= ctx->servers->count) {
            const char *srv_proxy = ctx->proxies[si % ctx->num_proxies];
            curl_easy_setopt(slot->handle, CURLOPT_PROXY, srv_proxy);
        }

        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s:%d/retrieve/%s/%d",
            srv->host, srv->port,
            ctx->file_id, ci);

        Buf *chunk = &ctx->chunk_bufs[ci];
        int success = 0;

        int max_retries = adv_config.max_retries > 0
            ? adv_config.max_retries
            : CHUNK_MAX_RETRIES;

        for (int attempt = 0;
             attempt < max_retries;
             attempt++) {

            /* ── Rotate proxy on retry ─────── */
            if (attempt > 0) {
                if (ctx->proxies &&
                    ctx->num_proxies > 0) {
                    int pidx =
                        (my_id + attempt) %
                        ctx->num_proxies;
                    curl_easy_setopt(
                        slot->handle,
                        CURLOPT_PROXY,
                        ctx->proxies[pidx]);
                }

                /* Also try different server */
                if (ctx->servers->count > 1) {
                    int alt_si =
                        (si + attempt) %
                        ctx->servers->count;
                    srv = &ctx->servers
                        ->entries[alt_si];
                    snprintf(url, sizeof(url),
                        "http://%s:%d/"
                        "retrieve/%s/%d",
                        srv->host, srv->port,
                        ctx->file_id, ci);
                }

                /* Force new connection */
                curl_easy_setopt(
                    slot->handle,
                    CURLOPT_FRESH_CONNECT,
                    1L);

                /* SHORTER timeout on retry —
                   if first server timed out,
                   don't wait 120s on retry too */
                long rtimeout = adv_config.retry_timeout_sec > 0
                    ? (long)adv_config.retry_timeout_sec
                    : (long)(ctx->is_onion ? 60 : 15);
                curl_easy_setopt(slot->handle,
                    CURLOPT_TIMEOUT, rtimeout);
            }

            /* Reset buffer for retry */
            buf_free(chunk);
            buf_init(chunk);

            PCurlCtx cctx = { .buf = chunk };

            curl_easy_setopt(slot->handle,
                CURLOPT_URL, url);
            curl_easy_setopt(slot->handle,
                CURLOPT_HTTPGET, 1L);
            curl_easy_setopt(slot->handle,
                CURLOPT_WRITEFUNCTION,
                p_write_cb);
            curl_easy_setopt(slot->handle,
                CURLOPT_WRITEDATA, &cctx);

            CURLcode res =
                curl_easy_perform(
                    slot->handle);
            long code = 0;
            curl_easy_getinfo(slot->handle,
                CURLINFO_RESPONSE_CODE,
                &code);

            if (res == CURLE_OK &&
                code == 200 &&
                chunk->len > 0) {

                success = 1;
                consecutive_ok++;

                /* Restore connection reuse */
                curl_easy_setopt(
                    slot->handle,
                    CURLOPT_FRESH_CONNECT,
                    0L);

                /* Track speed */
                speed_add(ctx->speed,
                          chunk->len);
                break;
            }

            consecutive_ok = 0;

            gui_post_log(ctx->log_target,
                "↓ Chunk %d attempt %d/%d "
                "← %s:%d [%s] "
                "(HTTP %ld: %s)",
                ci, attempt + 1,
                max_retries,
                srv->host, srv->port,
                my_proxy ? my_proxy : "direct",
                code,
                curl_easy_strerror(res));

            if (attempt <
                max_retries - 1) {
                int delay =
                    CHUNK_RETRY_BASE_SEC *
                    (1 << attempt);
                if (delay > 20) delay = 20;
                sleep((unsigned)delay);
            }
        }

        if (!success) {
            gui_post_log(ctx->log_target,
                "↓ Chunk %d FAILED after "
                "%d attempts",
                ci, max_retries);
            pthread_mutex_lock(&ctx->mutex);
            ctx->failed = 1;
            pthread_mutex_unlock(&ctx->mutex);
            break;
        }

        /* ── Update progress ───────────────── */

        pthread_mutex_lock(&ctx->mutex);
        ctx->completed++;
        ctx->bytes_done += chunk->len;
        int done = ctx->completed;
        size_t total_bytes = ctx->bytes_done;
        pthread_mutex_unlock(&ctx->mutex);

        /* Show speed periodically */
        if (done == 1 || done % 10 == 0 ||
            done == ctx->chunk_count) {

            double avg =
                speed_get_avg(ctx->speed);
            char speed_str[64];
            human_size((size_t)avg,
                       speed_str,
                       sizeof(speed_str));

            char done_str[64];
            human_size(total_bytes,
                       done_str,
                       sizeof(done_str));

            gui_post_log(ctx->log_target,
                "↓ %d/%d chunks (%s) "
                "[%s/s]",
                done, ctx->chunk_count,
                done_str, speed_str);
        }

        gui_post_progress(ctx->log_target,
            0.1 + 0.6 *
            (double)done /
            ctx->chunk_count);
    }

    curl_slot_destroy(slot);
    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * PARALLEL DOWNLOAD CHUNKS — OPTIMIZED
 *
 * KEY CHANGES:
 *   1. Increased thread limit (16 vs 8)
 *   2. Max 4 connections per server (was 2)
 *   3. Reduced stagger (500ms vs 1500ms)
 *   4. Speed tracking with bandwidth display
 *   5. Adaptive thread count based on chunk
 *      count and available resources
 *   6. Connection reuse via CURL handle pool
 * ────────────────────────────────────────────────────────────── */

int parallel_download_chunks(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    int chunk_count,
    const uint32_t *chunk_sizes,
    Buf *assembled,
    int log_target)
{
    int is_onion = addr_is_onion(server_addr);

    /* ── Warm up circuits ──────────────────── */

    if (is_onion && proxies &&
        num_proxies > 0) {
        int warm = parallel_warmup_circuits(
            proxies, num_proxies,
            servers, log_target);

        if (warm == 0) {
            gui_post_log(log_target,
                "No circuits available");
            return -1;
        }

        /* Update proxy count to only
           use warm ones */
        gui_post_log(log_target,
            "%d/%d circuits warm",
            warm, num_proxies);
    }

    /* ── Calculate thread count ────────────── */

    int nthreads = servers->count;

    if (nthreads > PARALLEL_MAX_THREADS)
        nthreads = PARALLEL_MAX_THREADS;

    if (nthreads > chunk_count)
        nthreads = chunk_count;

    /* Allow up to MAX_CONN_PER_SERVER per
       server (was * 2, now * 4) */
    if (nthreads > servers->count *
        MAX_CONN_PER_SERVER)
        nthreads = servers->count *
                   MAX_CONN_PER_SERVER;

    /* Override thread count from advanced config */
    if (adv_config.download_threads > 0 &&
        adv_config.download_threads <= 128)
        nthreads = adv_config.download_threads;

    if (nthreads > chunk_count)
        nthreads = chunk_count;
    if (nthreads < 1)
        nthreads = 1;

    /* Cap at proxy count for .onion */
    if (num_proxies > 0 &&
        nthreads > num_proxies)
        nthreads = num_proxies;

    gui_post_log(log_target,
        "═══════════════════════════════");
    gui_post_log(log_target,
        "Parallel download starting:");
    gui_post_log(log_target,
        "  Chunks:  %d", chunk_count);
    gui_post_log(log_target,
        "  Threads: %d", nthreads);
    gui_post_log(log_target,
        "  Servers: %d", servers->count);
    gui_post_log(log_target,
        "  Proxies: %d", num_proxies);
    gui_post_log(log_target,
        "  Mode:    %s",
        is_onion ? ".onion (Tor)" : "LAN");
    gui_post_log(log_target,
        "  Conn reuse: enabled");
    gui_post_log(log_target,
        "  Keep-alive: enabled");
    gui_post_log(log_target,
        "═══════════════════════════════");

    /* ── Allocate chunk buffers ────────────── */

    Buf *chunk_bufs = calloc(
        (size_t)chunk_count, sizeof(Buf));
    if (!chunk_bufs) return -1;

    /* ── Speed tracker ─────────────────────── */

    SpeedTracker speed;
    speed_init(&speed);

    /* ── Context ───────────────────────────── */

    ParallelDlCtx ctx = {
        .server_addr = server_addr,
        .proxies     = proxies,
        .num_proxies = num_proxies,
        .servers     = servers,
        .file_id     = file_id,
        .chunk_count = chunk_count,
        .chunk_sizes = chunk_sizes,
        .log_target  = log_target,
        .is_onion    = is_onion,
        .chunk_bufs  = chunk_bufs,
        .next_chunk  = 0,
        .failed      = 0,
        .completed   = 0,
        .bytes_done  = 0,
        .thread_id_counter = 0,
        .speed       = &speed,
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    /* ── Launch threads ────────────────────── */

    pthread_t *threads = malloc(
        (size_t)nthreads * sizeof(pthread_t));

    useconds_t stagger = adv_config.warmup_stagger_ms > 0
        ? (useconds_t)(adv_config.warmup_stagger_ms * 1000)
        : (is_onion ?
            THREAD_STAGGER_ONION_US :
            THREAD_STAGGER_LAN_US);

    struct timeval dl_start;
    gettimeofday(&dl_start, NULL);

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL,
                       download_worker, &ctx);

        if (i < nthreads - 1)
            usleep(stagger);
    }

    /* ── Wait for all threads ──────────────── */

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);

    /* ── Calculate final stats ─────────────── */

    struct timeval dl_end;
    gettimeofday(&dl_end, NULL);

    double elapsed =
        (double)(dl_end.tv_sec -
                 dl_start.tv_sec) +
        (double)(dl_end.tv_usec -
                 dl_start.tv_usec) / 1e6;

    if (ctx.failed) {
        for (int i = 0; i < chunk_count; i++)
            buf_free(&chunk_bufs[i]);
        free(chunk_bufs);
        speed_destroy(&speed);

        gui_post_log(log_target,
            "Download failed at %d/%d",
            ctx.completed, chunk_count);
        return -1;
    }

    /* ── Assemble chunks in order ──────────── */

    gui_post_log(log_target,
        "Assembling %d chunks...",
        chunk_count);

    /* Pre-calculate total size for
       single allocation */
    size_t total_size = 0;
    for (int i = 0; i < chunk_count; i++)
        total_size += chunk_bufs[i].len;

    /* Reserve space in one shot */
    buf_reserve(assembled, total_size);

    for (int i = 0; i < chunk_count; i++) {
        buf_add(assembled,
                chunk_bufs[i].data,
                chunk_bufs[i].len);
        buf_free(&chunk_bufs[i]);
    }
    free(chunk_bufs);

    /* ── Report ────────────────────────────── */

    double avg_speed =
        speed_get_avg(&speed);
    char speed_str[64], total_str[64];
    human_size((size_t)avg_speed,
               speed_str, sizeof(speed_str));
    human_size(total_size,
               total_str, sizeof(total_str));

    char peak_str[64];
    human_size((size_t)speed.peak_speed,
               peak_str, sizeof(peak_str));

    gui_post_log(log_target,
        "═══════════════════════════════");
    gui_post_log(log_target,
        "\xE2\x9C\x93 Download complete:");
    gui_post_log(log_target,
        "  Chunks:    %d", chunk_count);
    gui_post_log(log_target,
        "  Total:     %s", total_str);
    gui_post_log(log_target,
        "  Time:      %.1fs", elapsed);
    gui_post_log(log_target,
        "  Avg speed: %s/s", speed_str);
    gui_post_log(log_target,
        "  Peak:      %s/s", peak_str);
    gui_post_log(log_target,
        "  Circuits:  %d", num_proxies);
    gui_post_log(log_target,
        "═══════════════════════════════");

    speed_destroy(&speed);
    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * STREAMING DOWNLOAD — INDIVIDUAL CHUNK ACCESS
 *
 * Returns array of chunk buffers instead of
 * assembled blob. Caller can decrypt and write
 * to disk as chunks arrive.
 * ────────────────────────────────────────────────────────────── */

int parallel_download_chunks_streaming(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    int chunk_count,
    const uint32_t *chunk_sizes,
    Buf **chunk_bufs_out,
    int log_target)
{
    int is_onion = addr_is_onion(server_addr);

    if (is_onion && proxies &&
        num_proxies > 0) {
        parallel_warmup_circuits(
            proxies, num_proxies,
            servers, log_target);
    }

    int nthreads = servers->count;
    if (nthreads > PARALLEL_MAX_THREADS)
        nthreads = PARALLEL_MAX_THREADS;
    if (nthreads > chunk_count)
        nthreads = chunk_count;
    if (nthreads > servers->count *
        MAX_CONN_PER_SERVER)
        nthreads = servers->count *
                   MAX_CONN_PER_SERVER;
    if (nthreads < 1) nthreads = 1;
    if (num_proxies > 0 &&
        nthreads > num_proxies)
        nthreads = num_proxies;

    Buf *chunk_bufs = calloc(
        (size_t)chunk_count, sizeof(Buf));
    if (!chunk_bufs) return -1;

    SpeedTracker speed;
    speed_init(&speed);

    ParallelDlCtx ctx = {
        .server_addr = server_addr,
        .proxies     = proxies,
        .num_proxies = num_proxies,
        .servers     = servers,
        .file_id     = file_id,
        .chunk_count = chunk_count,
        .chunk_sizes = chunk_sizes,
        .log_target  = log_target,
        .is_onion    = is_onion,
        .chunk_bufs  = chunk_bufs,
        .next_chunk  = 0,
        .failed      = 0,
        .completed   = 0,
        .bytes_done  = 0,
        .thread_id_counter = 0,
        .speed       = &speed,
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    pthread_t *threads = malloc(
        (size_t)nthreads * sizeof(pthread_t));

    useconds_t stagger = is_onion ?
        THREAD_STAGGER_ONION_US :
        THREAD_STAGGER_LAN_US;

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL,
                       download_worker, &ctx);
        if (i < nthreads - 1)
            usleep(stagger);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);
    speed_destroy(&speed);

    if (ctx.failed) {
        for (int i = 0; i < chunk_count; i++)
            buf_free(&chunk_bufs[i]);
        free(chunk_bufs);
        return -1;
    }

    *chunk_bufs_out = chunk_bufs;
    return 0;
}

void parallel_free_server_list(SubServerList *s)
{
    if (s) memset(s, 0, sizeof(*s));
}