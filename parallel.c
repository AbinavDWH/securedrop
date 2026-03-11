#include "parallel.h"
#include "gui_helpers.h"
#include "util.h"
#include "app.h"

#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define CHUNK_MAX_RETRIES     4
#define CHUNK_RETRY_BASE_SEC  3
#define ONION_TIMEOUT_SEC   180
#define ONION_CONNECT_SEC    90
#define LAN_TIMEOUT_SEC      60
#define LAN_CONNECT_SEC      15
#define THREAD_STAGGER_USEC  1500000  /* 1.5s */

typedef struct {
    Buf *buf;
} PCurlCtx;

static size_t p_write_cb(void *data, size_t size,
                         size_t nmemb, void *userp)
{
    PCurlCtx *ctx = userp;
    size_t total = size * nmemb;
    buf_add(ctx->buf, data, total);
    return total;
}

static int addr_is_onion(const char *host)
{
    return (host && strstr(host, ".onion"));
}

/* ────────────────────────────────────────────────────────────
   GET SUB-SERVER LIST
   ──────────────────────────────────────────────────────────── */

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
        curl_easy_setopt(c, CURLOPT_PROXY, proxy);

    Buf resp;
    buf_init(&resp);
    PCurlCtx ctx = { .buf = &resp };

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                     p_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT,
                     30L);

    CURLcode res = curl_easy_perform(c);
    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE,
                      &http_code);
    curl_easy_cleanup(c);

    if (res != CURLE_OK || http_code != 200) {
        gui_post_log(log_target,
            "No sub-servers (HTTP %ld: %s)",
            http_code, curl_easy_strerror(res));
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
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *colon = strrchr(line, ':');
        if (colon && colon != line) {
            SubServerEntry *e =
                &out->entries[out->count];

            size_t hlen = (size_t)(colon - line);
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

/* ────────────────────────────────────────────────────────────
   WARM UP ONE PROXY → ONE .ONION
   
   Establishes the Tor circuit before real work.
   First contact to a .onion through a fresh circuit
   takes 10-60 seconds — do this upfront.
   ──────────────────────────────────────────────────────────── */

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
        curl_easy_setopt(c, CURLOPT_PROXY, proxy);

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 90L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT,
                     60L);

    /* Suppress body output */
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                     p_write_cb);
    Buf discard;
    buf_init(&discard);
    PCurlCtx dctx = { .buf = &discard };
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &dctx);

    CURLcode res = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE,
                      &code);
    curl_easy_cleanup(c);
    buf_free(&discard);

    if (res == CURLE_OK) {
        gui_post_log(log_target,
            "  \xE2\x9C\x93 Circuit[%d] warm "
            "(%s → %.20s...)",
            circuit_idx,
            proxy ? proxy : "direct",
            target_host);
        return 0;
    }

    gui_post_log(log_target,
        "  \xE2\x9C\x97 Circuit[%d] cold: %s",
        circuit_idx, curl_easy_strerror(res));
    return -1;
}

/* ────────────────────────────────────────────────────────────
   WARM UP ALL CIRCUITS (called before parallel work)
   ──────────────────────────────────────────────────────────── */

typedef struct {
    const char          *proxy;
    const char          *host;
    int                  port;
    int                  log_target;
    int                  idx;
    int                  result;
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

    /* Only warm up for .onion targets */
    if (!addr_is_onion(servers->entries[0].host))
        return num_proxies;

    gui_post_log(log_target,
        "Warming up %d circuits "
        "(first .onion contact is slow)...",
        num_proxies);

    int n = num_proxies;
    WarmupArg *args = calloc((size_t)n,
                             sizeof(WarmupArg));
    pthread_t *threads = malloc(
        (size_t)n * sizeof(pthread_t));

    for (int i = 0; i < n; i++) {
        int si = i % servers->count;
        args[i].proxy      = proxies[i];
        args[i].host       = servers->entries[si].host;
        args[i].port       = servers->entries[si].port;
        args[i].log_target = log_target;
        args[i].idx        = i;
        args[i].result     = -1;

        pthread_create(&threads[i], NULL,
                       warmup_thread, &args[i]);

        /* Stagger to avoid hammering Tor */
        if (i < n - 1)
            usleep(1000000); /* 1 second apart */
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

/* ────────────────────────────────────────────────────────────
   UPLOAD WORKER — WITH RETRY AND CIRCUIT ROTATION
   ──────────────────────────────────────────────────────────── */

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

    /* Assign stable thread ID for proxy affinity */
    pthread_mutex_lock(&ctx->mutex);
    int my_id = ctx->thread_id_counter++;
    pthread_mutex_unlock(&ctx->mutex);

    long timeout    = ctx->is_onion ?
                      ONION_TIMEOUT_SEC :
                      LAN_TIMEOUT_SEC;
    long connect_to = ctx->is_onion ?
                      ONION_CONNECT_SEC :
                      LAN_CONNECT_SEC;

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

        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s:%d/store/%s/%d",
            srv->host, srv->port,
            ctx->file_id, ci);

        const uint8_t *chunk_data =
            ctx->payload + ctx->chunk_offsets[ci];
        uint32_t chunk_size = ctx->chunk_sizes[ci];

        int success = 0;

        for (int attempt = 0;
             attempt < CHUNK_MAX_RETRIES;
             attempt++) {

            /* Rotate proxy on retry */
            const char *my_proxy = NULL;
            if (ctx->proxies &&
                ctx->num_proxies > 0) {
                int pidx = (my_id + attempt) %
                           ctx->num_proxies;
                my_proxy = ctx->proxies[pidx];
            }

            CURL *c = curl_easy_init();
            if (!c) break;

            if (my_proxy && my_proxy[0])
                curl_easy_setopt(c,
                    CURLOPT_PROXY, my_proxy);

            struct curl_slist *hdr = NULL;
            hdr = curl_slist_append(hdr,
                "Content-Type: "
                "application/octet-stream");

            curl_easy_setopt(c, CURLOPT_URL, url);
            curl_easy_setopt(c, CURLOPT_POST, 1L);
            curl_easy_setopt(c,
                CURLOPT_POSTFIELDS, chunk_data);
            curl_easy_setopt(c,
                CURLOPT_POSTFIELDSIZE_LARGE,
                (curl_off_t)chunk_size);
            curl_easy_setopt(c,
                CURLOPT_HTTPHEADER, hdr);
            curl_easy_setopt(c,
                CURLOPT_TIMEOUT, timeout);
            curl_easy_setopt(c,
                CURLOPT_CONNECTTIMEOUT,
                connect_to);

            /* Low-speed abort: if < 100 B/s
               for 60s, give up this attempt */
            curl_easy_setopt(c,
                CURLOPT_LOW_SPEED_LIMIT, 100L);
            curl_easy_setopt(c,
                CURLOPT_LOW_SPEED_TIME, 60L);

            CURLcode res = curl_easy_perform(c);
            long code = 0;
            curl_easy_getinfo(c,
                CURLINFO_RESPONSE_CODE, &code);

            curl_slist_free_all(hdr);
            curl_easy_cleanup(c);

            if (res == CURLE_OK && code == 200) {
                success = 1;
                break;
            }

            gui_post_log(ctx->log_target,
                "↑ Chunk %d attempt %d/%d "
                "failed → %s:%d [%s] "
                "(HTTP %ld: %s)",
                ci, attempt + 1,
                CHUNK_MAX_RETRIES,
                srv->host, srv->port,
                my_proxy ? my_proxy : "direct",
                code, curl_easy_strerror(res));

            if (attempt < CHUNK_MAX_RETRIES - 1) {
                int delay = CHUNK_RETRY_BASE_SEC *
                            (1 << attempt);
                /* 3, 6, 12 seconds */
                if (delay > 30) delay = 30;
                sleep((unsigned)delay);
            }
        }

        if (!success) {
            gui_post_log(ctx->log_target,
                "↑ Chunk %d PERMANENTLY FAILED "
                "after %d attempts",
                ci, CHUNK_MAX_RETRIES);
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
            (double)done / ctx->chunk_count);
    }

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   PARALLEL UPLOAD CHUNKS
   ──────────────────────────────────────────────────────────── */

int parallel_upload_chunks(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    const uint8_t *payload, size_t payload_len,
    int chunk_count,
    const size_t *chunk_offsets,
    const uint32_t *chunk_sizes,
    int log_target)
{
    int is_onion = addr_is_onion(server_addr);

    /* Warm up circuits before real work */
    if (is_onion && proxies && num_proxies > 0) {
        int warm = parallel_warmup_circuits(
            proxies, num_proxies,
            servers, log_target);

        if (warm == 0) {
            gui_post_log(log_target,
                "No circuits warmed — "
                "aborting parallel upload");
            return -1;
        }
    }

    int nthreads = PARALLEL_MAX_THREADS;
    if (nthreads > chunk_count)
        nthreads = chunk_count;
    if (nthreads > servers->count * 2)
        nthreads = servers->count * 2;
    if (nthreads < 1) nthreads = 1;

    if (num_proxies > 0) {
        if (nthreads > num_proxies)
            nthreads = num_proxies;
        gui_post_log(log_target,
            "Tor mode: %d circuits, %d threads",
            num_proxies, nthreads);
    }

    gui_post_log(log_target,
        "Parallel upload: %d chunks, "
        "%d threads, %d servers, %d proxies",
        chunk_count, nthreads,
        servers->count, num_proxies);

    ParallelUpCtx ctx = {
        .server_addr      = server_addr,
        .proxies          = proxies,
        .num_proxies      = num_proxies,
        .servers          = servers,
        .file_id          = file_id,
        .payload          = payload,
        .payload_len      = payload_len,
        .chunk_count      = chunk_count,
        .chunk_offsets    = chunk_offsets,
        .chunk_sizes      = chunk_sizes,
        .log_target       = log_target,
        .is_onion         = is_onion,
        .next_chunk       = 0,
        .failed           = 0,
        .completed        = 0,
        .thread_id_counter = 0,
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    pthread_t *threads = malloc(
        (size_t)nthreads * sizeof(pthread_t));

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL,
                       upload_worker, &ctx);

        /* Stagger thread launches for .onion */
        if (is_onion && i < nthreads - 1)
            usleep(THREAD_STAGGER_USEC);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);

    if (ctx.failed) {
        gui_post_log(log_target,
            "Upload failed at %d/%d chunks",
            ctx.completed, chunk_count);
        return -1;
    }

    gui_post_log(log_target,
        "\xE2\x9C\x93 All %d chunks uploaded "
        "via %d circuits",
        chunk_count, num_proxies);
    return 0;
}

/* ────────────────────────────────────────────────────────────
   DOWNLOAD WORKER — WITH RETRY AND CIRCUIT ROTATION
   ──────────────────────────────────────────────────────────── */

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
    int                  thread_id_counter;
} ParallelDlCtx;

static void *download_worker(void *arg)
{
    ParallelDlCtx *ctx = arg;

    pthread_mutex_lock(&ctx->mutex);
    int my_id = ctx->thread_id_counter++;
    pthread_mutex_unlock(&ctx->mutex);

    long timeout    = ctx->is_onion ?
                      ONION_TIMEOUT_SEC :
                      LAN_TIMEOUT_SEC;
    long connect_to = ctx->is_onion ?
                      ONION_CONNECT_SEC :
                      LAN_CONNECT_SEC;

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

        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s:%d/retrieve/%s/%d",
            srv->host, srv->port,
            ctx->file_id, ci);

        Buf *chunk = &ctx->chunk_bufs[ci];
        int success = 0;

        for (int attempt = 0;
             attempt < CHUNK_MAX_RETRIES;
             attempt++) {

            /* Rotate proxy on retry:
               Thread 0 uses proxy 0,1,2,3...
               Thread 1 uses proxy 1,2,3,0...
               This ensures retries try a
               different Tor circuit */
            const char *my_proxy = NULL;
            if (ctx->proxies &&
                ctx->num_proxies > 0) {
                int pidx = (my_id + attempt) %
                           ctx->num_proxies;
                my_proxy = ctx->proxies[pidx];
            }

            /* Also try a different sub-server
               on retry */
            if (attempt > 0 &&
                ctx->servers->count > 1) {
                int alt_si = (si + attempt) %
                             ctx->servers->count;
                srv = &ctx->servers->entries[alt_si];
                snprintf(url, sizeof(url),
                    "http://%s:%d/retrieve/%s/%d",
                    srv->host, srv->port,
                    ctx->file_id, ci);
            }

            /* Reset buffer for retry */
            buf_free(chunk);
            buf_init(chunk);

            CURL *c = curl_easy_init();
            if (!c) break;

            if (my_proxy && my_proxy[0])
                curl_easy_setopt(c,
                    CURLOPT_PROXY, my_proxy);

            PCurlCtx cctx = { .buf = chunk };

            curl_easy_setopt(c, CURLOPT_URL, url);
            curl_easy_setopt(c,
                CURLOPT_WRITEFUNCTION, p_write_cb);
            curl_easy_setopt(c,
                CURLOPT_WRITEDATA, &cctx);
            curl_easy_setopt(c,
                CURLOPT_TIMEOUT, timeout);
            curl_easy_setopt(c,
                CURLOPT_CONNECTTIMEOUT,
                connect_to);

            /* Low-speed abort */
            curl_easy_setopt(c,
                CURLOPT_LOW_SPEED_LIMIT, 100L);
            curl_easy_setopt(c,
                CURLOPT_LOW_SPEED_TIME, 60L);

            CURLcode res = curl_easy_perform(c);
            long code = 0;
            curl_easy_getinfo(c,
                CURLINFO_RESPONSE_CODE, &code);
            curl_easy_cleanup(c);

            if (res == CURLE_OK && code == 200 &&
                chunk->len > 0) {
                success = 1;
                break;
            }

            gui_post_log(ctx->log_target,
                "↓ Chunk %d attempt %d/%d "
                "failed ← %s:%d [%s] "
                "(HTTP %ld: %s)",
                ci, attempt + 1,
                CHUNK_MAX_RETRIES,
                srv->host, srv->port,
                my_proxy ? my_proxy : "direct",
                code, curl_easy_strerror(res));

            if (attempt < CHUNK_MAX_RETRIES - 1) {
                int delay = CHUNK_RETRY_BASE_SEC *
                            (1 << attempt);
                if (delay > 30) delay = 30;
                sleep((unsigned)delay);
            }
        }

        if (!success) {
            gui_post_log(ctx->log_target,
                "↓ Chunk %d PERMANENTLY FAILED "
                "after %d attempts",
                ci, CHUNK_MAX_RETRIES);
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
                "↓ %d/%d chunks downloaded",
                done, ctx->chunk_count);
        }

        gui_post_progress(ctx->log_target,
            0.1 + 0.6 *
            (double)done / ctx->chunk_count);
    }

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   PARALLEL DOWNLOAD CHUNKS
   ──────────────────────────────────────────────────────────── */

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

    /* Warm up circuits */
    if (is_onion && proxies && num_proxies > 0) {
        int warm = parallel_warmup_circuits(
            proxies, num_proxies,
            servers, log_target);

        if (warm == 0) {
            gui_post_log(log_target,
                "No circuits warmed — "
                "aborting parallel download");
            return -1;
        }

        gui_post_log(log_target,
            "%d/%d circuits verified warm",
            warm, num_proxies);
    }

    int nthreads = PARALLEL_MAX_THREADS;
    if (nthreads > chunk_count)
        nthreads = chunk_count;
    if (nthreads > servers->count * 2)
        nthreads = servers->count * 2;
    if (nthreads < 1) nthreads = 1;

    if (num_proxies > 0) {
        if (nthreads > num_proxies)
            nthreads = num_proxies;
        gui_post_log(log_target,
            "Tor mode: %d circuits, %d threads",
            num_proxies, nthreads);
    }

    gui_post_log(log_target,
        "Parallel download: %d chunks, "
        "%d threads, %d servers, %d proxies",
        chunk_count, nthreads,
        servers->count, num_proxies);

    Buf *chunk_bufs = calloc((size_t)chunk_count,
                             sizeof(Buf));
    if (!chunk_bufs) return -1;

    ParallelDlCtx ctx = {
        .server_addr      = server_addr,
        .proxies          = proxies,
        .num_proxies      = num_proxies,
        .servers          = servers,
        .file_id          = file_id,
        .chunk_count      = chunk_count,
        .chunk_sizes      = chunk_sizes,
        .log_target       = log_target,
        .is_onion         = is_onion,
        .chunk_bufs       = chunk_bufs,
        .next_chunk       = 0,
        .failed           = 0,
        .completed        = 0,
        .thread_id_counter = 0,
    };
    pthread_mutex_init(&ctx.mutex, NULL);

    pthread_t *threads = malloc(
        (size_t)nthreads * sizeof(pthread_t));

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL,
                       download_worker, &ctx);

        /* Stagger thread launches for .onion */
        if (is_onion && i < nthreads - 1)
            usleep(THREAD_STAGGER_USEC);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    pthread_mutex_destroy(&ctx.mutex);

    if (ctx.failed) {
        for (int i = 0; i < chunk_count; i++)
            buf_free(&chunk_bufs[i]);
        free(chunk_bufs);
        gui_post_log(log_target,
            "Download failed at %d/%d",
            ctx.completed, chunk_count);
        return -1;
    }

    for (int i = 0; i < chunk_count; i++) {
        buf_add(assembled,
                chunk_bufs[i].data,
                chunk_bufs[i].len);
        buf_free(&chunk_bufs[i]);
    }
    free(chunk_bufs);

    gui_post_log(log_target,
        "\xE2\x9C\x93 All %d chunks downloaded "
        "via %d circuits",
        chunk_count, num_proxies);
    return 0;
}

void parallel_free_server_list(SubServerList *s)
{
    if (s) memset(s, 0, sizeof(*s));
}