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

#include "client.h"
#include "protocol.h"
#include "crypto.h"
#include "gui_helpers.h"
#include "util.h"
#include "tor.h"
#include "parallel.h"
#include "tor_pool.h"

#include <curl/curl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

typedef struct { Buf *buf; } CurlCtx;

static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp)
{
    CurlCtx *ctx = userp;
    if (size != 0 && nmemb > SIZE_MAX / size)
        return 0;
    size_t total = size * nmemb;
    if (ctx->buf->len + total < ctx->buf->len)
        return 0;
    if (ctx->buf->len + total > (size_t)512 * 1024 * 1024)
        return 0;
    buf_add(ctx->buf, data, total);
    return total;
}

typedef struct {
    char *filepath;
    char *server_addr;
    char *password;
} UploadArgs;

typedef struct {
    char *server_addr;
    char *file_id;
    char *password;
} DownloadArgs;

static int is_onion_address(const char *addr)
{
    if (!addr) return 0;
    return (strstr(addr, ".onion") != NULL);
}

/* ────────────────────────────────────────────────────────────
   FIND SOCKS5 PROXY
   ──────────────────────────────────────────────────────────── */

static int check_port(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               &tv, sizeof(tv));

    int ok = (connect(s, (struct sockaddr *)&addr,
                      sizeof(addr)) == 0);
    close(s);
    return ok;
}

static int find_tor_socks_port(char *proxy_out,
                               size_t proxy_sz,
                               int log_target)
{
    int ports[] = { 9050, 9150, 0 };

    for (int i = 0; ports[i] != 0; i++) {
        if (check_port(ports[i])) {
            snprintf(proxy_out, proxy_sz,
                "socks5h://127.0.0.1:%d",
                ports[i]);
            gui_post_log(log_target,
                "\xE2\x9C\x93 Main Tor SOCKS5 "
                "on port %d", ports[i]);
            return ports[i];
        }
    }

    return 0;
}

/* ────────────────────────────────────────────────────────────
   CONFIGURE CURL WITH PROXY
   ──────────────────────────────────────────────────────────── */

static int setup_curl_proxy(CURL *c,
                            const char *addr,
                            int log_target)
{
    int onion = is_onion_address(addr);

    char proxy[256];
    int port = find_tor_socks_port(proxy,
        sizeof(proxy), log_target);

    if (port > 0) {
        curl_easy_setopt(c, CURLOPT_PROXY,
                         proxy);
        return 1;
    }

    if (onion) {
        gui_post_log(log_target,
            "ERROR: .onion requires Tor!");
        gui_post_log(log_target,
            "  sudo apt install tor");
        gui_post_log(log_target,
            "  sudo systemctl start tor");
        return -1;
    }

    gui_post_log(log_target,
        "No Tor — direct connection");
    return 0;
}

/* ────────────────────────────────────────────────────────────
   RESOLVE MAIN PROXY
   ──────────────────────────────────────────────────────────── */

static int resolve_main_proxy(
    const char *server_addr,
    char *proxy_out,
    size_t proxy_sz,
    int log_target)
{
    proxy_out[0] = '\0';

    int port = find_tor_socks_port(proxy_out,
        proxy_sz, log_target);
    if (port > 0)
        return 1;

    if (is_onion_address(server_addr))
        return -1;

    return 0;
}

/* ────────────────────────────────────────────────────────────
   LOG SERVER RESPONSE BODY (for error diagnosis)
   ──────────────────────────────────────────────────────────── */

static void log_server_response(Buf *resp,
                                int log_target)
{
    if (!resp || resp->len == 0)
        return;

    if (resp->len > 2048)
        return;

    char *msg = malloc(resp->len + 1);
    if (!msg) return;

    memcpy(msg, resp->data, resp->len);
    msg[resp->len] = '\0';

    /* Trim trailing whitespace */
    size_t len = resp->len;
    while (len > 0 &&
           (msg[len - 1] == '\n' ||
            msg[len - 1] == '\r' ||
            msg[len - 1] == ' '))
        msg[--len] = '\0';

    if (len > 0)
        gui_post_log(log_target,
            "Server: %s", msg);

    free(msg);
}

/* ────────────────────────────────────────────────────────────
   UPLOAD THREAD
   ──────────────────────────────────────────────────────────── */

static void *upload_thread(void *arg)
{
    UploadArgs *ua    = arg;
    char *filepath    = ua->filepath;
    char *server_addr = ua->server_addr;
    char *password    = ua->password;
    free(ua);

    gui_post_log(LOG_SEND,
        "Starting upload: %s", filepath);

    struct timeval upload_start;
    gettimeofday(&upload_start, NULL);

    /* ── Build encrypted payload ─────────────── */

    Buf payload;
    buf_init(&payload);

    char file_id[FILE_ID_HEX_LEN + 1] = {0};

    if (protocol_build_upload(filepath, password,
                              &payload, file_id,
                              LOG_SEND) != 0) {
        gui_post_log(LOG_SEND,
            "Encryption failed");
        goto done;
    }

    gui_post_fileid(file_id);
    gui_post_log(LOG_SEND,
        "File ID: %s", file_id);

    /* ═════════════════════════════════════════════
       PARALLEL UPLOAD ATTEMPT
       ═════════════════════════════════════════════ */
    {
        char main_proxy[256] = {0};
        const char *mp = NULL;

        int pxr = resolve_main_proxy(
            server_addr, main_proxy,
            sizeof(main_proxy), LOG_SEND);

        if (pxr < 0) {
            gui_post_log(LOG_SEND,
                "No Tor for .onion — "
                "cannot do parallel");
            goto single_upload;
        }
        if (pxr > 0)
            mp = main_proxy;

        /* Step 1: Get sub-server list
           Retry for .onion servers since
           sub-server Tor may still be
           bootstrapping (takes 1-2 min) */
        SubServerList servers;
        int nsrv = 0;
        int max_srv_attempts =
            is_onion_address(server_addr) ? 6 : 1;

        for (int sa = 0;
             sa < max_srv_attempts && nsrv <= 0;
             sa++) {
            if (sa > 0) {
                gui_post_log(LOG_SEND,
                    "Waiting for sub-servers "
                    "(%d/%d, 15s)...",
                    sa + 1, max_srv_attempts);
                gui_post_progress(LOG_SEND,
                    0.3 + 0.05 * sa);
                sleep(15);
            }
            nsrv = parallel_get_server_list(
                server_addr, mp,
                &servers, LOG_SEND);
        }

        if (nsrv <= 0) {
            gui_post_log(LOG_SEND,
                "No sub-servers available "
                "after %d attempts",
                max_srv_attempts);
            goto single_upload;
        }

        gui_post_log(LOG_SEND,
            "Parallel: %d sub-servers found",
            nsrv);

        for (int i = 0; i < nsrv && i < 3; i++)
            gui_post_log(LOG_SEND,
                "  Sub[%d]: %s:%d", i,
                servers.entries[i].host,
                servers.entries[i].port);

        /* Step 2: Start Tor proxy pool */
        int num_pool_proxies = 0;
        const char *pool_proxies[TOR_POOL_MAX];

        if (is_onion_address(server_addr)) {
            gui_post_log(LOG_SEND,
                "Starting Tor proxy pool...");

            int pool_count = nsrv;
            if (pool_count > TOR_POOL_MAX)
                pool_count = TOR_POOL_MAX;
            if (pool_count < 4)
                pool_count = 4;

            int ready = tor_pool_start(
                pool_count, LOG_SEND);

            if (ready > 0) {
                num_pool_proxies =
                    tor_pool_get_all_proxies(
                        pool_proxies,
                        TOR_POOL_MAX);

                gui_post_log(LOG_SEND,
                    "\xE2\x9C\x93 %d "
                    "independent Tor "
                    "circuits ready",
                    num_pool_proxies);
            } else {
                gui_post_log(LOG_SEND,
                    "Pool failed — using "
                    "single circuit");

                if (mp) {
                    pool_proxies[0] = mp;
                    num_pool_proxies = 1;
                }
            }
        }

        /* Step 3: Parse payload header to
           find chunk boundaries */

        const uint8_t *pp = payload.data;
        size_t rem = payload.len;
        int parse_ok = 1;
        uint32_t tmp32 = 0;

        #define PSKIP(n) do { \
            if (!parse_ok) break; \
            if (rem < (size_t)(n)) \
                parse_ok = 0; \
            else { pp += (n); rem -= (n); } \
        } while(0)

        #define PREAD32(var) do { \
            if (!parse_ok) break; \
            if (rem < 4) parse_ok = 0; \
            else { (var) = rd32(pp); \
                   pp += 4; rem -= 4; } \
        } while(0)

        PSKIP(4);            /* magic */
        PSKIP(4);            /* version */
        PSKIP(SALT_LEN);
        PSKIP(HASH_LEN);

        PREAD32(tmp32);
        PSKIP(tmp32);        /* rsa pub */

        PSKIP(AES_IV_LEN);
        PSKIP(AES_TAG_LEN);
        PREAD32(tmp32);
        PSKIP(tmp32);        /* enc priv */

        PREAD32(tmp32);
        PSKIP(tmp32);        /* master */

        PREAD32(tmp32);
        PSKIP(tmp32);        /* filename */

        PSKIP(8);            /* filesize */

        uint32_t chunk_count = 0;
        PREAD32(chunk_count);

        #undef PSKIP
        #undef PREAD32

        if (!parse_ok || chunk_count == 0 ||
            chunk_count > 100000) {
            gui_post_log(LOG_SEND,
                "Header parse failed "
                "(ok=%d, chunks=%u)",
                parse_ok, chunk_count);
            goto parallel_fail;
        }

        size_t chunk_data_start =
            (size_t)(pp - payload.data);

        gui_post_log(LOG_SEND,
            "Parsed: %u chunks, "
            "header=%zu bytes",
            chunk_count, chunk_data_start);

        /* Step 4: Build chunk offset/size
           tables */

        uint32_t *chunk_sizes =
            malloc(chunk_count *
                   sizeof(uint32_t));
        size_t *chunk_offsets =
            malloc(chunk_count *
                   sizeof(size_t));

        if (!chunk_sizes || !chunk_offsets) {
            free(chunk_sizes);
            free(chunk_offsets);
            gui_post_log(LOG_SEND,
                "Memory allocation failed");
            goto parallel_fail;
        }

        {
            const uint8_t *cp = pp;
            size_t cr = rem;

            for (uint32_t ci = 0;
                 ci < chunk_count; ci++) {
                if (cr < 8) {
                    gui_post_log(LOG_SEND,
                        "Chunk %u: truncated",
                        ci);
                    free(chunk_sizes);
                    free(chunk_offsets);
                    goto parallel_fail;
                }

                chunk_offsets[ci] =
                    (size_t)(cp - payload.data);

                uint32_t ctlen = rd32(cp + 4);
                size_t total = 4 + 4 +
                    AES_IV_LEN + AES_TAG_LEN +
                    ctlen;

                chunk_sizes[ci] =
                    (uint32_t)total;

                if (cr < total) {
                    gui_post_log(LOG_SEND,
                        "Chunk %u: incomplete "
                        "(%zu < %zu)",
                        ci, cr, total);
                    free(chunk_sizes);
                    free(chunk_offsets);
                    goto parallel_fail;
                }

                cp += total;
                cr -= total;
            }
        }

        /* Step 5: Upload chunks via pool */

        gui_post_log(LOG_SEND,
            "═══════════════════════════════");
        gui_post_log(LOG_SEND,
            "Uploading %u chunks via "
            "%d circuits to %d servers...",
            chunk_count, num_pool_proxies,
            nsrv);
        gui_post_log(LOG_SEND,
            "═══════════════════════════════");

        int prc = parallel_upload_chunks(
            server_addr,
            num_pool_proxies > 0 ?
                pool_proxies : NULL,
            num_pool_proxies,
            &servers, file_id,
            payload.data, payload.len,
            (int)chunk_count,
            chunk_offsets, chunk_sizes,
            LOG_SEND);

        free(chunk_sizes);
        free(chunk_offsets);

        if (prc != 0) {
            gui_post_log(LOG_SEND,
                "Chunk upload failed");
            goto parallel_fail;
        }

        gui_post_log(LOG_SEND,
            "All chunks uploaded — "
            "sending metadata...");

        /* ── Step 6: Send metadata with
           file_id in URL ─────────────────────
           
           FIX: Include file_id in the URL path.
           
           The client computed:
             file_id = SHA256(full payload)
           
           Chunks are stored on sub-servers
           under this file_id.
           
           The server receives only the metadata
           header (no chunks). If the server
           computes SHA256(metadata only), it
           gets a DIFFERENT hash.
           
           By passing file_id in the URL, the
           server stores metadata under the
           CORRECT file_id that matches the
           chunks on sub-servers.
           ──────────────────────────────────── */

        char meta_url[1024];
        snprintf(meta_url, sizeof(meta_url),
            "http://%s/upload-parallel/%s",
            server_addr, file_id);

        gui_post_log(LOG_SEND,
            "Metadata → %s", meta_url);

        CURL *mc = curl_easy_init();
        if (!mc) {
            gui_post_log(LOG_SEND,
                "curl init failed for "
                "metadata");
            goto parallel_fail;
        }

        if (mp)
            curl_easy_setopt(mc,
                CURLOPT_PROXY, mp);

        struct curl_slist *mh = NULL;
        mh = curl_slist_append(mh,
            "Content-Type: "
            "application/octet-stream");

        Buf mresp;
        buf_init(&mresp);
        CurlCtx mctx = { .buf = &mresp };

        curl_easy_setopt(mc,
            CURLOPT_URL, meta_url);
        curl_easy_setopt(mc,
            CURLOPT_POST, 1L);
        curl_easy_setopt(mc,
            CURLOPT_POSTFIELDS,
            payload.data);
        curl_easy_setopt(mc,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)chunk_data_start);
        curl_easy_setopt(mc,
            CURLOPT_HTTPHEADER, mh);
        curl_easy_setopt(mc,
            CURLOPT_WRITEFUNCTION,
            write_callback);
        curl_easy_setopt(mc,
            CURLOPT_WRITEDATA, &mctx);
        curl_easy_setopt(mc,
            CURLOPT_TIMEOUT, 120L);
        curl_easy_setopt(mc,
            CURLOPT_CONNECTTIMEOUT, 60L);

        CURLcode mres =
            curl_easy_perform(mc);
        long mcode = 0;
        curl_easy_getinfo(mc,
            CURLINFO_RESPONSE_CODE,
            &mcode);

        curl_slist_free_all(mh);
        curl_easy_cleanup(mc);

        if (mres == CURLE_OK &&
            mcode == 200) {

            log_server_response(&mresp,
                                LOG_SEND);
            buf_free(&mresp);
            parallel_free_server_list(
                &servers);

            struct timeval upload_end;
            gettimeofday(&upload_end, NULL);
            double elapsed =
                (double)(upload_end.tv_sec -
                         upload_start.tv_sec) +
                (double)(upload_end.tv_usec -
                         upload_start.tv_usec)
                / 1e6;

            char sz[64];
            human_size(payload.len, sz,
                       sizeof(sz));
            double speed =
                (elapsed > 0.1) ?
                (double)payload.len / elapsed
                : 0;
            char sp[64];
            human_size((size_t)speed, sp,
                       sizeof(sp));

            gui_post_log(LOG_SEND,
                "═══════════════════════"
                "═══════════");
            gui_post_log(LOG_SEND,
                "\xE2\x9C\x93 Upload "
                "successful (parallel)!");
            gui_post_log(LOG_SEND,
                "  File ID: %s", file_id);
            gui_post_log(LOG_SEND,
                "  Size:    %s", sz);
            gui_post_log(LOG_SEND,
                "  Time:    %.1fs", elapsed);
            gui_post_log(LOG_SEND,
                "  Speed:   %s/s", sp);
            gui_post_log(LOG_SEND,
                "  Circuits: %d",
                num_pool_proxies);
            gui_post_log(LOG_SEND,
                "═══════════════════════"
                "═══════════");

            gui_post_progress(LOG_SEND, 1.0);
            goto done;
        }

        /* Metadata upload failed */
        gui_post_log(LOG_SEND,
            "Metadata failed (HTTP %ld: %s)",
            mcode,
            curl_easy_strerror(mres));
        log_server_response(&mresp, LOG_SEND);
        buf_free(&mresp);

    parallel_fail:
        parallel_free_server_list(&servers);
        gui_post_log(LOG_SEND,
            "Parallel failed — "
            "falling back to single");
    }

    single_upload:

    /* ═════════════════════════════════════════════
       SINGLE-CONNECTION UPLOAD
       ═════════════════════════════════════════════ */
    {
        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s/upload", server_addr);

        gui_post_log(LOG_SEND,
            "Target: %s", url);
        gui_post_progress(LOG_SEND, 0.65);

        CURL *c = curl_easy_init();
        if (!c) {
            gui_post_log(LOG_SEND,
                "curl init failed");
            goto done;
        }

        int pr = setup_curl_proxy(c,
            server_addr, LOG_SEND);
        if (pr < 0) {
            curl_easy_cleanup(c);
            goto done;
        }

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers,
            "Content-Type: "
            "application/octet-stream");

        curl_easy_setopt(c,
            CURLOPT_URL, url);
        curl_easy_setopt(c,
            CURLOPT_POST, 1L);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDS,
            payload.data);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)payload.len);
        curl_easy_setopt(c,
            CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(c,
            CURLOPT_TIMEOUT, 600L);
        curl_easy_setopt(c,
            CURLOPT_CONNECTTIMEOUT, 120L);

        /* Keep-alive for large uploads */
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPINTVL, 15L);

        Buf resp_buf;
        buf_init(&resp_buf);
        CurlCtx cctx = { .buf = &resp_buf };
        curl_easy_setopt(c,
            CURLOPT_WRITEFUNCTION,
            write_callback);
        curl_easy_setopt(c,
            CURLOPT_WRITEDATA, &cctx);

        gui_post_progress(LOG_SEND, 0.7);
        gui_post_log(LOG_SEND, "Uploading...");

        CURLcode res = curl_easy_perform(c);
        long http_code = 0;
        curl_easy_getinfo(c,
            CURLINFO_RESPONSE_CODE,
            &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(c);

        if (res != CURLE_OK) {
            gui_post_log(LOG_SEND,
                "Transfer error: %s",
                curl_easy_strerror(res));
        } else if (http_code == 200) {
            struct timeval upload_end;
            gettimeofday(&upload_end, NULL);
            double elapsed =
                (double)(upload_end.tv_sec -
                         upload_start.tv_sec) +
                (double)(upload_end.tv_usec -
                         upload_start.tv_usec)
                / 1e6;

            gui_post_log(LOG_SEND,
                "\xE2\x9C\x93 Upload "
                "successful! (%.1fs)",
                elapsed);
            gui_post_log(LOG_SEND,
                "File ID: %s", file_id);
            log_server_response(&resp_buf,
                                LOG_SEND);
        } else {
            gui_post_log(LOG_SEND,
                "Server error: HTTP %ld",
                http_code);
            log_server_response(&resp_buf,
                                LOG_SEND);
        }

        buf_free(&resp_buf);
        gui_post_progress(LOG_SEND, 1.0);
    }

done:
    buf_free(&payload);
    if (password) {
        secure_wipe(password, strlen(password));
        free(password);
    }
    free(filepath);
    free(server_addr);
    return NULL;
}

/* ────────────────────────────────────────────────────────────
   DOWNLOAD THREAD
   ──────────────────────────────────────────────────────────── */

static void *download_thread(void *arg)
{
    DownloadArgs *da  = arg;
    char *server_addr = da->server_addr;
    char *file_id     = da->file_id;
    char *password    = da->password;
    free(da);

    gui_post_log(LOG_RECV,
        "Starting download...");
    gui_post_log(LOG_RECV,
        "Requesting file %.16s...", file_id);

    struct timeval dl_start;
    gettimeofday(&dl_start, NULL);

    Buf req_body;
    buf_init(&req_body);
    buf_add(&req_body, file_id, FILE_ID_HEX_LEN);
    buf_add(&req_body, "\0", 1);
    buf_add(&req_body, password,
            strlen(password));

    /* ═════════════════════════════════════════════
       PARALLEL DOWNLOAD ATTEMPT
       ═════════════════════════════════════════════ */
    {
        char main_proxy[256] = {0};
        const char *mp = NULL;

        int pxr = resolve_main_proxy(
            server_addr, main_proxy,
            sizeof(main_proxy), LOG_RECV);

        if (pxr < 0) {
            gui_post_log(LOG_RECV,
                "No Tor proxy found — "
                "skipping parallel");
            goto single_download;
        }
        if (pxr > 0) mp = main_proxy;

        /* Step 1: Get sub-server list
           Retry for .onion servers */
        SubServerList servers;
        int nsrv = 0;
        int max_srv_attempts =
            is_onion_address(server_addr) ? 4 : 1;

        for (int sa = 0;
             sa < max_srv_attempts && nsrv <= 0;
             sa++) {
            if (sa > 0) {
                gui_post_log(LOG_RECV,
                    "Waiting for sub-servers "
                    "(%d/%d, 10s)...",
                    sa + 1, max_srv_attempts);
                gui_post_progress(LOG_RECV,
                    0.1 + 0.05 * sa);
                sleep(10);
            }
            nsrv = parallel_get_server_list(
                server_addr, mp,
                &servers, LOG_RECV);
        }

        if (nsrv <= 0) {
            gui_post_log(LOG_RECV,
                "No sub-servers after "
                "%d attempts — single mode",
                max_srv_attempts);
            goto single_download;
        }

        gui_post_log(LOG_RECV,
            "Parallel: %d sub-servers", nsrv);

        for (int i = 0; i < nsrv && i < 3; i++)
            gui_post_log(LOG_RECV,
                "  Sub[%d]: %s:%d", i,
                servers.entries[i].host,
                servers.entries[i].port);

        /* Step 2: Start Tor pool for .onion */
        int num_pool_proxies = 0;
        const char *pool_proxies[TOR_POOL_MAX];

        if (is_onion_address(server_addr)) {
            gui_post_log(LOG_RECV,
                "Starting Tor proxy pool...");

            int pool_count = nsrv;
            if (pool_count > TOR_POOL_MAX)
                pool_count = TOR_POOL_MAX;
            if (pool_count < 4)
                pool_count = 4;

            int ready = tor_pool_start(
                pool_count, LOG_RECV);

            if (ready > 0) {
                num_pool_proxies =
                    tor_pool_get_all_proxies(
                        pool_proxies,
                        TOR_POOL_MAX);
                gui_post_log(LOG_RECV,
                    "\xE2\x9C\x93 %d circuits "
                    "ready",
                    num_pool_proxies);
            } else {
                gui_post_log(LOG_RECV,
                    "Pool failed — using "
                    "single circuit");
                if (mp) {
                    pool_proxies[0] = mp;
                    num_pool_proxies = 1;
                }
            }
        }

        /* Step 3: Get metadata from server
           
           Try multiple endpoint names because
           server might use either:
             /download-parallel
             /download-meta
        */

        const char *meta_endpoints[] = {
            "/download-parallel",
            "/download-meta",
            NULL
        };

        Buf meta_resp;
        buf_init(&meta_resp);
        int meta_ok = 0;
        long meta_code = 0;

        for (int ep = 0;
             meta_endpoints[ep] != NULL;
             ep++) {

            char meta_url[1024];
            snprintf(meta_url, sizeof(meta_url),
                "http://%s%s",
                server_addr,
                meta_endpoints[ep]);

            gui_post_log(LOG_RECV,
                "Trying %s...",
                meta_endpoints[ep]);

            CURL *mc = curl_easy_init();
            if (!mc) continue;

            if (mp)
                curl_easy_setopt(mc,
                    CURLOPT_PROXY, mp);

            struct curl_slist *mh = NULL;
            mh = curl_slist_append(mh,
                "Content-Type: "
                "application/octet-stream");

            /* Reset buffer for each attempt */
            buf_free(&meta_resp);
            buf_init(&meta_resp);
            CurlCtx mctx = {
                .buf = &meta_resp
            };

            curl_easy_setopt(mc,
                CURLOPT_URL, meta_url);
            curl_easy_setopt(mc,
                CURLOPT_POST, 1L);
            curl_easy_setopt(mc,
                CURLOPT_POSTFIELDS,
                req_body.data);
            curl_easy_setopt(mc,
                CURLOPT_POSTFIELDSIZE_LARGE,
                (curl_off_t)req_body.len);
            curl_easy_setopt(mc,
                CURLOPT_HTTPHEADER, mh);
            curl_easy_setopt(mc,
                CURLOPT_WRITEFUNCTION,
                write_callback);
            curl_easy_setopt(mc,
                CURLOPT_WRITEDATA, &mctx);
            curl_easy_setopt(mc,
                CURLOPT_TIMEOUT, 120L);
            curl_easy_setopt(mc,
                CURLOPT_CONNECTTIMEOUT, 60L);

            CURLcode mres =
                curl_easy_perform(mc);
            curl_easy_getinfo(mc,
                CURLINFO_RESPONSE_CODE,
                &meta_code);

            curl_slist_free_all(mh);
            curl_easy_cleanup(mc);

            if (mres == CURLE_OK &&
                meta_code == 200 &&
                meta_resp.len > 8) {

                char sz[64];
                human_size(meta_resp.len, sz,
                           sizeof(sz));
                gui_post_log(LOG_RECV,
                    "\xE2\x9C\x93 Metadata "
                    "received (%s via %s)",
                    sz, meta_endpoints[ep]);
                meta_ok = 1;
                break;
            }

            /* Log failure reason */
            gui_post_log(LOG_RECV,
                "  %s → HTTP %ld (%s)",
                meta_endpoints[ep],
                meta_code,
                curl_easy_strerror(mres));
            log_server_response(&meta_resp,
                                LOG_RECV);
        }

        if (!meta_ok) {
            gui_post_log(LOG_RECV,
                "No parallel endpoint "
                "responded successfully");
            buf_free(&meta_resp);
            goto parallel_dl_fail;
        }

        /* Step 4: Parse metadata header to
           get chunk count */

        const uint8_t *xp = meta_resp.data;
        size_t xrem = meta_resp.len;
        int xok = 1;
        uint32_t xtmp = 0;

        #define XSKIP(n) do { \
            if (!xok) break; \
            if (xrem < (size_t)(n)) xok = 0; \
            else { xp += (n); xrem -= (n); } \
        } while(0)

        #define XREAD32(var) do { \
            if (!xok) break; \
            if (xrem < 4) xok = 0; \
            else { (var) = rd32(xp); \
                   xp += 4; xrem -= 4; } \
        } while(0)

        XSKIP(4);            /* magic */
        XSKIP(4);            /* version */
        XSKIP(SALT_LEN);     /* salt */
        XSKIP(HASH_LEN);     /* verify */
        XREAD32(xtmp);
        XSKIP(xtmp);         /* rsa pub */
        XSKIP(AES_IV_LEN);
        XSKIP(AES_TAG_LEN);
        XREAD32(xtmp);
        XSKIP(xtmp);         /* enc priv */
        XREAD32(xtmp);
        XSKIP(xtmp);         /* master */
        XREAD32(xtmp);
        XSKIP(xtmp);         /* filename */
        XSKIP(8);            /* filesize */

        uint32_t chunk_count = 0;
        XREAD32(chunk_count);

        #undef XSKIP
        #undef XREAD32

        if (!xok || chunk_count == 0 ||
            chunk_count > 100000) {
            gui_post_log(LOG_RECV,
                "Metadata parse failed "
                "(ok=%d, chunks=%u)",
                xok, chunk_count);
            buf_free(&meta_resp);
            goto parallel_dl_fail;
        }

        gui_post_log(LOG_RECV,
            "═══════════════════════════════");
        gui_post_log(LOG_RECV,
            "Downloading %u chunks via "
            "%d circuits from %d servers...",
            chunk_count, num_pool_proxies,
            nsrv);
        gui_post_log(LOG_RECV,
            "═══════════════════════════════");

        /* Step 5: Download all chunks in
           parallel from sub-servers */

        uint32_t *chunk_sizes =
            calloc(chunk_count,
                   sizeof(uint32_t));

        /* Start assembled buffer with
           metadata as header */
        Buf assembled;
        buf_init(&assembled);

        /* Pre-allocate: metadata + estimated
           chunk data */
        buf_reserve(&assembled,
            meta_resp.len +
            (size_t)chunk_count * CHUNK_SIZE);

        buf_add(&assembled,
                meta_resp.data,
                meta_resp.len);

        int prc = parallel_download_chunks(
            server_addr,
            num_pool_proxies > 0 ?
                pool_proxies : NULL,
            num_pool_proxies,
            &servers, file_id,
            (int)chunk_count, chunk_sizes,
            &assembled, LOG_RECV);

        free(chunk_sizes);
        buf_free(&meta_resp);

        if (prc == 0) {
            char sz[64];
            human_size(assembled.len, sz,
                       sizeof(sz));
            gui_post_log(LOG_RECV,
                "Download complete (%s) — "
                "decrypting...", sz);
            gui_post_progress(
                LOG_RECV, 0.7);

            int drc = protocol_parse_download(
                assembled.data, assembled.len,
                password, LOG_RECV);

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

                gui_post_log(LOG_RECV,
                    "═══════════════════════"
                    "═══════════");
                gui_post_log(LOG_RECV,
                    "\xE2\x9C\x93 Download "
                    "successful (parallel)!");
                gui_post_log(LOG_RECV,
                    "  Time:     %.1fs",
                    elapsed);
                gui_post_log(LOG_RECV,
                    "  Circuits: %d",
                    num_pool_proxies);
                gui_post_log(LOG_RECV,
                    "  Servers:  %d", nsrv);
                gui_post_log(LOG_RECV,
                    "═══════════════════════"
                    "═══════════");

                gui_post_progress(
                    LOG_RECV, 1.0);
                goto done;
            }

            gui_post_log(LOG_RECV,
                "Parallel decrypt failed — "
                "data may be corrupted");
        } else {
            buf_free(&assembled);
            gui_post_log(LOG_RECV,
                "Parallel chunk download "
                "failed (%d chunks "
                "incomplete)", chunk_count);
        }

    parallel_dl_fail:
        parallel_free_server_list(&servers);
        gui_post_log(LOG_RECV,
            "Parallel failed — "
            "falling back to single "
            "connection");
    }

    single_download:

    /* ═════════════════════════════════════════════
       SINGLE-CONNECTION DOWNLOAD
       ═════════════════════════════════════════════ */
    {
        char url[1024];
        snprintf(url, sizeof(url),
            "http://%s/download", server_addr);

        gui_post_log(LOG_RECV,
            "Target: %s", url);
        gui_post_progress(LOG_RECV, 0.05);

        CURL *c = curl_easy_init();
        if (!c) {
            gui_post_log(LOG_RECV,
                "curl init failed");
            goto done;
        }

        int pr = setup_curl_proxy(c,
            server_addr, LOG_RECV);
        if (pr < 0) {
            curl_easy_cleanup(c);
            goto done;
        }

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers,
            "Content-Type: "
            "application/octet-stream");

        Buf resp_buf;
        buf_init(&resp_buf);
        CurlCtx cctx = { .buf = &resp_buf };

        curl_easy_setopt(c,
            CURLOPT_URL, url);
        curl_easy_setopt(c,
            CURLOPT_POST, 1L);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDS,
            req_body.data);
        curl_easy_setopt(c,
            CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t)req_body.len);
        curl_easy_setopt(c,
            CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(c,
            CURLOPT_WRITEFUNCTION,
            write_callback);
        curl_easy_setopt(c,
            CURLOPT_WRITEDATA, &cctx);
        curl_easy_setopt(c,
            CURLOPT_TIMEOUT, 600L);
        curl_easy_setopt(c,
            CURLOPT_CONNECTTIMEOUT, 120L);

        /* Keep-alive */
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(c,
            CURLOPT_TCP_KEEPINTVL, 15L);

        /* Larger receive buffer */
        curl_easy_setopt(c,
            CURLOPT_BUFFERSIZE, 262144L);

        gui_post_progress(LOG_RECV, 0.1);
        gui_post_log(LOG_RECV,
            "Downloading (single)...");

        CURLcode res = curl_easy_perform(c);
        long http_code = 0;
        curl_easy_getinfo(c,
            CURLINFO_RESPONSE_CODE,
            &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(c);

        if (res != CURLE_OK) {
            gui_post_log(LOG_RECV,
                "Connection error: %s",
                curl_easy_strerror(res));
            buf_free(&resp_buf);
            goto done;
        }

        if (http_code != 200) {
            gui_post_log(LOG_RECV,
                "HTTP %ld from server",
                http_code);
            log_server_response(&resp_buf,
                                LOG_RECV);

            if (http_code == 403) {
                gui_post_log(LOG_RECV,
                    "403 = wrong password "
                    "or file not found");
                gui_post_log(LOG_RECV,
                    "Check: correct file ID "
                    "and password?");
            } else if (http_code == 404) {
                gui_post_log(LOG_RECV,
                    "404 = file ID not found "
                    "on server");
            } else if (http_code == 500) {
                gui_post_log(LOG_RECV,
                    "500 = server internal "
                    "error (check server "
                    "logs)");
            }

            buf_free(&resp_buf);
            goto done;
        }

        gui_post_progress(LOG_RECV, 0.3);

        char sz[64];
        human_size(resp_buf.len, sz,
                   sizeof(sz));
        gui_post_log(LOG_RECV,
            "Received %s — decrypting...",
            sz);

        int drc = protocol_parse_download(
            resp_buf.data, resp_buf.len,
            password, LOG_RECV);

        buf_free(&resp_buf);

        if (drc == 0) {
            struct timeval dl_end;
            gettimeofday(&dl_end, NULL);
            double elapsed =
                (double)(dl_end.tv_sec -
                         dl_start.tv_sec) +
                (double)(dl_end.tv_usec -
                         dl_start.tv_usec)
                / 1e6;

            gui_post_log(LOG_RECV,
                "\xE2\x9C\x93 Download "
                "successful! (%.1fs, "
                "single connection)",
                elapsed);
        } else {
            gui_post_log(LOG_RECV,
                "Decryption failed — "
                "wrong password or "
                "corrupted data");
        }

        gui_post_progress(LOG_RECV, 1.0);
    }

done:
    buf_free(&req_body);
    if (password) {
        secure_wipe(password, strlen(password));
        free(password);
    }
    free(file_id);
    free(server_addr);
    return NULL;
}

/* ────────────────────────────────────────────────────────────
   PUBLIC API
   ──────────────────────────────────────────────────────────── */

void client_upload_file(const char *filepath,
                        const char *server_addr,
                        const char *password)
{
    UploadArgs *ua   = malloc(sizeof(UploadArgs));
    ua->filepath     = strdup(filepath);
    ua->server_addr  = strdup(server_addr);
    ua->password     = strdup(password);

    pthread_t t;
    pthread_create(&t, NULL, upload_thread, ua);
    pthread_detach(t);
}

void client_download_file(const char *server_addr,
                          const char *file_id,
                          const char *password)
{
    DownloadArgs *da = malloc(sizeof(DownloadArgs));
    da->server_addr  = strdup(server_addr);
    da->file_id      = strdup(file_id);
    da->password     = strdup(password);

    pthread_t t;
    pthread_create(&t, NULL, download_thread, da);
    pthread_detach(t);
}