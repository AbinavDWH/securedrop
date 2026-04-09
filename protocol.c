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

#include "protocol.h"
#include "storage.h"
#include "gui_helpers.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sys/time.h>

/* ──────────────────────────────────────────────────────────────
 * SERVER-SIDE PARALLEL RETRIEVE HELPER
 * ────────────────────────────────────────────────────────────── */

#define DL_RETRIEVE_BATCH  8

typedef struct {
    const char *file_id;
    uint32_t    chunk_idx;
    int         sub_server_idx;
    Buf         result;
    int         ok;
    int         log_target;
} RetrieveJob;

static void *retrieve_worker(void *arg)
{
    RetrieveJob *job = arg;
    buf_init(&job->result);

    job->ok = storage_retrieve_chunk(
        job->file_id,
        job->chunk_idx,
        job->sub_server_idx,
        &job->result,
        job->log_target);

    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * BUILD UPLOAD PAYLOAD
 * Called by sender. Encrypts file locally before sending.
 * ────────────────────────────────────────────────────────────── */

int protocol_build_upload(const char *filepath,
                          const char *password,
                          Buf *payload,
                          char *file_id_out,
                          int log_target)
{
    int ret = -1;
    FILE *fp = NULL;
    unsigned char *cbuf = NULL, *ctbuf = NULL;

    unsigned char master_key[MASTER_KEY_LEN];
    unsigned char pwd_salt[SALT_LEN];
    unsigned char pwd_key[AES_KEY_LEN];
    unsigned char pwd_verify[HASH_LEN];
    unsigned char rsa_pub[4096], rsa_priv[8192];
    size_t rsa_pub_len = sizeof(rsa_pub);
    size_t rsa_priv_len = sizeof(rsa_priv);
    unsigned char enc_rsa_priv[8192];
    size_t enc_rsa_priv_len = 0;
    unsigned char rsa_priv_iv[AES_IV_LEN];
    unsigned char rsa_priv_tag[AES_TAG_LEN];
    unsigned char enc_master[512];
    size_t enc_master_len = sizeof(enc_master);
    int have_keys = 0;

    gui_post_log(log_target, "Preparing upload...");

    if (secure_random(master_key, MASTER_KEY_LEN) != 0) {
        gui_post_log(log_target, "CSPRNG failure");
        goto cleanup;
    }

    if (secure_random(pwd_salt, SALT_LEN) != 0)
        goto cleanup;

    if (password_derive_key(password, pwd_salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0) {
        gui_post_log(log_target, "Key derivation failed");
        goto cleanup;
    }

    if (password_make_verifier(pwd_key, pwd_verify) != 0)
        goto cleanup;

    gui_post_log(log_target, "Generating RSA-4096 keypair...");
    if (gen_rsa_keys_to_pem(rsa_pub, &rsa_pub_len,
                            rsa_priv, &rsa_priv_len) != 0) {
        gui_post_log(log_target, "RSA keygen failed");
        goto cleanup;
    }
    have_keys = 1;

    if (encrypt_blob(pwd_key,
                     rsa_priv, rsa_priv_len,
                     rsa_priv_iv, enc_rsa_priv,
                     &enc_rsa_priv_len,
                     rsa_priv_tag) != 0) {
        gui_post_log(log_target, "RSA privkey encryption failed");
        goto cleanup;
    }

    if (rsa_encrypt_pem(rsa_pub, rsa_pub_len,
                        master_key, MASTER_KEY_LEN,
                        enc_master, &enc_master_len) != 0) {
        gui_post_log(log_target, "Master key encryption failed");
        goto cleanup;
    }

    fp = fopen(filepath, "rb");
    if (!fp) {
        gui_post_log(log_target, "Cannot open: %s", filepath);
        goto cleanup;
    }
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;

    char sz[64];
    human_size((size_t)fsz, sz, sizeof(sz));
    gui_post_log(log_target, "File: %s (%s)", basename, sz);

    uint32_t chunk_count = (fsz == 0) ? 1 :
        (uint32_t)((fsz + CHUNK_SIZE - 1) / CHUNK_SIZE);

    buf_add(payload, PROTO_MAGIC_UPLOAD, 4);
    buf_u32(payload, PROTO_VERSION);
    buf_add(payload, pwd_salt, SALT_LEN);
    buf_add(payload, pwd_verify, HASH_LEN);

    buf_u32(payload, (uint32_t)rsa_pub_len);
    buf_add(payload, rsa_pub, rsa_pub_len);

    buf_add(payload, rsa_priv_iv, AES_IV_LEN);
    buf_add(payload, rsa_priv_tag, AES_TAG_LEN);
    buf_u32(payload, (uint32_t)enc_rsa_priv_len);
    buf_add(payload, enc_rsa_priv, enc_rsa_priv_len);

    buf_u32(payload, (uint32_t)enc_master_len);
    buf_add(payload, enc_master, enc_master_len);

    uint32_t fnl = (uint32_t)strlen(basename);
    buf_u32(payload, fnl);
    buf_add(payload, basename, fnl);
    buf_u64(payload, (uint64_t)fsz);
    buf_u32(payload, chunk_count);

    gui_post_log(log_target, "Encrypting %u chunks...",
                 chunk_count);

    cbuf  = malloc(CHUNK_SIZE);
    ctbuf = malloc(CHUNK_SIZE + 256);
    if (!cbuf || !ctbuf) goto cleanup;

    for (uint32_t i = 0; i < chunk_count; i++) {
        size_t want = CHUNK_SIZE;
        if ((long)((size_t)(i + 1) * CHUNK_SIZE) > fsz)
            want = (size_t)(fsz -
                   (long)((size_t)i * CHUNK_SIZE));
        if (fsz == 0) want = 0;

        size_t got = (want > 0) ?
            fread(cbuf, 1, want, fp) : 0;

        unsigned char ck[AES_KEY_LEN];
        if (derive_chunk_key(master_key, MASTER_KEY_LEN,
                             i, ck, AES_KEY_LEN) != 0) {
            secure_wipe(ck, AES_KEY_LEN);
            goto cleanup;
        }

        unsigned char iv[AES_IV_LEN], tag[AES_TAG_LEN];
        size_t ctlen = 0;
        if (encrypt_chunk(ck, i, cbuf, got,
                          iv, ctbuf, &ctlen, tag) != 0) {
            secure_wipe(ck, AES_KEY_LEN);
            goto cleanup;
        }
        secure_wipe(ck, AES_KEY_LEN);

        buf_u32(payload, i);
        buf_u32(payload, (uint32_t)ctlen);
        buf_add(payload, iv, AES_IV_LEN);
        buf_add(payload, tag, AES_TAG_LEN);
        buf_add(payload, ctbuf, ctlen);

        gui_post_progress(log_target,
            (double)(i + 1) / chunk_count * 0.6);
    }

    if (compute_sha256_hex(payload->data, payload->len,
                           file_id_out) != 0) {
        gui_post_log(log_target, "Hash computation failed");
        goto cleanup;
    }

    human_size(payload->len, sz, sizeof(sz));
    gui_post_log(log_target, "Payload ready: %s", sz);
    gui_post_log(log_target, "File ID: %.16s...", file_id_out);

    ret = 0;

cleanup:
    if (fp) fclose(fp);
    if (cbuf)  { secure_wipe(cbuf, CHUNK_SIZE); free(cbuf); }
    if (ctbuf) free(ctbuf);

    secure_wipe(master_key, MASTER_KEY_LEN);
    secure_wipe(pwd_key, AES_KEY_LEN);
    secure_wipe(pwd_verify, HASH_LEN);
    if (have_keys)
        secure_wipe(rsa_priv, rsa_priv_len);

    return ret;
}

/* ──────────────────────────────────────────────────────────────
 * PARSE UPLOAD — PARALLEL CHUNK STORAGE
 * ────────────────────────────────────────────────────────────── */

int protocol_parse_upload(const unsigned char *d, size_t len,
                          char *file_id_out,
                          int log_target)
{
    size_t p = 0;

    if (p + 4 > len) return -1;
    if (memcmp(d + p, PROTO_MAGIC_UPLOAD, 4) != 0) {
        gui_post_log(log_target, "Invalid upload magic");
        return -1;
    }
    p += 4;

    if (p + 4 > len) return -1;
    uint32_t version = rd32(d + p); p += 4;
    if (version != PROTO_VERSION) {
        gui_post_log(log_target,
            "Unsupported version: %u", version);
        return -1;
    }

    if (compute_sha256_hex(d, len, file_id_out) != 0)
        return -1;

    gui_post_log(log_target, "Upload file ID: %.16s...",
                 file_id_out);

    pthread_mutex_lock(&app.stored_mutex);
        if (app.stored_file_count >= MAX_STORED_FILES ||
        ensure_stored_capacity() != 0) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target, "Storage full");
        return -1;
    }

    StoredFileMeta *meta =
        &app.stored_files[app.stored_file_count];
    memset(meta, 0, sizeof(*meta));
    strncpy(meta->file_id, file_id_out, FILE_ID_HEX_LEN);

    if (p + SALT_LEN > len) goto fail_unlock;
    memcpy(meta->password_salt, d + p, SALT_LEN);
    p += SALT_LEN;

    if (p + HASH_LEN > len) goto fail_unlock;
    memcpy(meta->password_verify, d + p, HASH_LEN);
    p += HASH_LEN;

    if (p + 4 > len) goto fail_unlock;
    uint32_t pub_len = rd32(d + p); p += 4;
    if (pub_len > sizeof(meta->rsa_pub_pem) ||
        p + pub_len > len)
        goto fail_unlock;
    memcpy(meta->rsa_pub_pem, d + p, pub_len);
    meta->rsa_pub_len = pub_len;
    p += pub_len;

    if (p + AES_IV_LEN > len) goto fail_unlock;
    memcpy(meta->rsa_priv_iv, d + p, AES_IV_LEN);
    p += AES_IV_LEN;

    if (p + AES_TAG_LEN > len) goto fail_unlock;
    memcpy(meta->rsa_priv_tag, d + p, AES_TAG_LEN);
    p += AES_TAG_LEN;

    if (p + 4 > len) goto fail_unlock;
    uint32_t erp_len = rd32(d + p); p += 4;
    if (erp_len > sizeof(meta->enc_rsa_priv) ||
        p + erp_len > len)
        goto fail_unlock;
    memcpy(meta->enc_rsa_priv, d + p, erp_len);
    meta->erp_len = erp_len;
    p += erp_len;

    if (p + 4 > len) goto fail_unlock;
    uint32_t emk_len = rd32(d + p); p += 4;
    if (emk_len > sizeof(meta->enc_master_key) ||
        p + emk_len > len)
        goto fail_unlock;
    memcpy(meta->enc_master_key, d + p, emk_len);
    meta->emk_len = emk_len;
    p += emk_len;

    if (p + 4 > len) goto fail_unlock;
    uint32_t fnl = rd32(d + p); p += 4;
    if (fnl > sizeof(meta->original_name) - 1 ||
        p + fnl > len)
        goto fail_unlock;
    memcpy(meta->original_name, d + p, fnl);
    meta->original_name[fnl] = '\0';
    p += fnl;

    for (char *x = meta->original_name; *x; x++)
        if (*x == '/' || *x == '\\') *x = '_';
    if (meta->original_name[0] == '.')
        meta->original_name[0] = '_';

    if (p + 8 > len) goto fail_unlock;
    meta->original_size = (size_t)rd64(d + p);
    p += 8;

    if (p + 4 > len) goto fail_unlock;
    meta->chunk_count = rd32(d + p);
    p += 4;

    if (meta->chunk_count > MAX_CHUNKS) goto fail_unlock;

    meta->upload_time = time(NULL);

    uint32_t cc = meta->chunk_count;
    int stored_idx = app.stored_file_count;

    pthread_mutex_unlock(&app.stored_mutex);

    char sz_str[64];
    human_size(meta->original_size, sz_str, sizeof(sz_str));
    gui_post_log(log_target, "Storing: %s (%s, %u chunks)",
                 meta->original_name, sz_str, cc);

    const unsigned char **chunk_ptrs =
        calloc(cc, sizeof(unsigned char *));
    size_t *chunk_lens =
        calloc(cc, sizeof(size_t));

    if (!chunk_ptrs || !chunk_lens) {
        free(chunk_ptrs);
        free(chunk_lens);
        gui_post_log(log_target, "Memory allocation failed");
        return -1;
    }

    for (uint32_t i = 0; i < cc; i++) {
        if (p + 4 > len) goto fail_chunks;
        uint32_t gi = rd32(d + p); p += 4;
        (void)gi;

        if (p + 4 > len) goto fail_chunks;
        uint32_t ctlen = rd32(d + p); p += 4;

        if (ctlen > CHUNK_SIZE + 256) goto fail_chunks;

        size_t chunk_total = AES_IV_LEN + AES_TAG_LEN + ctlen;
        if (p + chunk_total > len) goto fail_chunks;

        size_t wire_start = p - 8;
        chunk_ptrs[i] = d + wire_start;
        chunk_lens[i] = 8 + chunk_total;

        p += chunk_total;
    }

    gui_post_log(log_target,
        "Parsed %u chunks, distributing in parallel...", cc);

    int *locations = calloc(cc, sizeof(int));
    if (!locations) goto fail_chunks;

    int rc = storage_store_chunks_parallel(
        file_id_out, (int)cc,
        chunk_ptrs, chunk_lens,
        locations, log_target);

    pthread_mutex_lock(&app.stored_mutex);
    if (stored_idx < MAX_STORED_FILES) {
        StoredFileMeta *final_meta = &app.stored_files[stored_idx];
        for (uint32_t i = 0; i < cc; i++)
            final_meta->chunk_locations[i] = locations[i];

        final_meta->distributed = (app.num_sub_servers > 0) ? 1 : 0;
        app.stored_file_count++;
        app.upload_count++;
    }

    StoredFileMeta meta_copy;
    memcpy(&meta_copy, &app.stored_files[stored_idx], sizeof(meta_copy));
    pthread_mutex_unlock(&app.stored_mutex);

    free(chunk_ptrs);
    free(chunk_lens);
    free(locations);

    storage_save_meta(&meta_copy, log_target);

    if (rc != 0)
        gui_post_log(log_target,
            "Upload partially stored (some chunks failed)");
    else
        gui_post_log(log_target,
            "Upload stored successfully (parallel)");

    gui_post_log(log_target, "File ID: %s", file_id_out);
    gui_post_progress(log_target, 1.0);

    return 0;

fail_chunks:
    free(chunk_ptrs);
    free(chunk_lens);
    gui_post_log(log_target,
        "Malformed upload payload (chunk parse)");
    return -1;

fail_unlock:
    pthread_mutex_unlock(&app.stored_mutex);
    gui_post_log(log_target, "Malformed upload payload");
    return -1;
}

/* ──────────────────────────────────────────────────────────────
 * BUILD DOWNLOAD RESPONSE — PARALLEL RETRIEVAL
 * ────────────────────────────────────────────────────────────── */

int protocol_build_download(const char *file_id,
                            const char *password,
                            Buf *response,
                            int log_target)
{
    StoredFileMeta *meta = NULL;
    pthread_mutex_lock(&app.stored_mutex);

    for (int i = 0; i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id) == 0) {
            meta = &app.stored_files[i];
            break;
        }
    }

    if (!meta) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target,
            "File ID not found: %.16s...", file_id);
        return -1;
    }

    StoredFileMeta mcopy;
    memcpy(&mcopy, meta, sizeof(mcopy));
    pthread_mutex_unlock(&app.stored_mutex);

    unsigned char pwd_key[AES_KEY_LEN];
    if (password_derive_key(password,
                            mcopy.password_salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0) {
        gui_post_log(log_target, "Key derivation failed");
        return -1;
    }

    if (password_check_verifier(pwd_key,
                                mcopy.password_verify) != 0) {
        gui_post_log(log_target,
            "WRONG PASSWORD for file %.16s...", file_id);
        secure_wipe(pwd_key, AES_KEY_LEN);
        return -1;
    }

    gui_post_log(log_target,
        "Password verified for %.16s...", file_id);

    /* Pre-allocate response buffer */
    size_t estimate = 4096 + mcopy.original_size +
                      mcopy.chunk_count * 64;
    buf_reserve(response, estimate);

    buf_add(response, PROTO_MAGIC_DOWNLOAD, 4);
    buf_u32(response, PROTO_VERSION);
    buf_add(response, mcopy.password_salt, SALT_LEN);
    buf_add(response, mcopy.password_verify, HASH_LEN);

    buf_u32(response, (uint32_t)mcopy.rsa_pub_len);
    buf_add(response, mcopy.rsa_pub_pem, mcopy.rsa_pub_len);

    buf_add(response, mcopy.rsa_priv_iv, AES_IV_LEN);
    buf_add(response, mcopy.rsa_priv_tag, AES_TAG_LEN);
    buf_u32(response, (uint32_t)mcopy.erp_len);
    buf_add(response, mcopy.enc_rsa_priv, mcopy.erp_len);

    buf_u32(response, (uint32_t)mcopy.emk_len);
    buf_add(response, mcopy.enc_master_key, mcopy.emk_len);

    uint32_t fnl = (uint32_t)strlen(mcopy.original_name);
    buf_u32(response, fnl);
    buf_add(response, mcopy.original_name, fnl);

    buf_u64(response, (uint64_t)mcopy.original_size);
    buf_u32(response, mcopy.chunk_count);

    /* ── Retrieve chunks in parallel batches ───────────────── */

    gui_post_log(log_target,
        "Retrieving %u chunks in parallel (batch=%d)...",
        mcopy.chunk_count, DL_RETRIEVE_BATCH);

    struct timeval t_start;
    gettimeofday(&t_start, NULL);

    uint32_t cc = mcopy.chunk_count;

    for (uint32_t base = 0; base < cc;
         base += DL_RETRIEVE_BATCH) {

        int batch_n = DL_RETRIEVE_BATCH;
        if (base + (uint32_t)batch_n > cc)
            batch_n = (int)(cc - base);

        pthread_t thr[DL_RETRIEVE_BATCH];
        RetrieveJob jobs[DL_RETRIEVE_BATCH];

        for (int j = 0; j < batch_n; j++) {
            uint32_t ci = base + (uint32_t)j;
            jobs[j] = (RetrieveJob){
                .file_id        = file_id,
                .chunk_idx      = ci,
                .sub_server_idx = mcopy.chunk_locations[ci],
                .ok             = -1,
                .log_target     = log_target,
            };
            pthread_create(&thr[j], NULL,
                           retrieve_worker, &jobs[j]);
        }

        for (int j = 0; j < batch_n; j++) {
            pthread_join(thr[j], NULL);

            uint32_t ci = base + (uint32_t)j;

            if (jobs[j].ok != 0) {
                gui_post_log(log_target,
                    "Failed to retrieve chunk %u", ci);
                for (int k = j; k < batch_n; k++)
                    buf_free(&jobs[k].result);
                secure_wipe(pwd_key, AES_KEY_LEN);
                return -1;
            }

            buf_add(response,
                    jobs[j].result.data,
                    jobs[j].result.len);
            buf_free(&jobs[j].result);
        }

        uint32_t done = base + (uint32_t)batch_n;
        gui_post_progress(log_target,
            (double)done / cc);

        if (done % 50 == 0 || done == cc)
            gui_post_log(log_target,
                "Retrieved %u/%u chunks", done, cc);
    }

    secure_wipe(pwd_key, AES_KEY_LEN);

    struct timeval t_end;
    gettimeofday(&t_end, NULL);
    double elapsed =
        (double)(t_end.tv_sec - t_start.tv_sec) +
        (double)(t_end.tv_usec - t_start.tv_usec) / 1e6;

    char sz[64];
    human_size(response->len, sz, sizeof(sz));
    gui_post_log(log_target,
        "Download response: %s (%.1fs)", sz, elapsed);

    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * PARSE DOWNLOAD RESPONSE — STREAMING DECRYPT + WRITE
 * ────────────────────────────────────────────────────────────── */

int protocol_parse_download(const unsigned char *d, size_t len,
                            const char *password,
                            int log_target)
{
    size_t p = 0;
    int ret = -1;

    unsigned char pwd_key[AES_KEY_LEN];
    unsigned char *rsa_priv = NULL;
    size_t rsa_priv_len = 0;
    unsigned char *pt_buf = NULL;
    char *wbuf = NULL;
    int have_pwd_key = 0;
    FILE *ofp = NULL;
    char outpath[2048] = {0};

    /* Verify magic */
    if (p + 4 > len) return -1;
    if (memcmp(d + p, PROTO_MAGIC_DOWNLOAD, 4) != 0) {
        gui_post_log(log_target, "Invalid download magic");
        return -1;
    }
    p += 4;

    /* Version */
    if (p + 4 > len) return -1;
    uint32_t version = rd32(d + p); p += 4;
    (void)version;

    /* Password salt */
    if (p + SALT_LEN > len) return -1;
    const unsigned char *salt = d + p; p += SALT_LEN;

    /* Password verify */
    if (p + HASH_LEN > len) return -1;
    const unsigned char *verify = d + p; p += HASH_LEN;

    /* Derive password key */
    gui_post_log(log_target, "Deriving password key...");
    if (password_derive_key(password, salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0)
        goto cleanup;
    have_pwd_key = 1;

    /* Verify password */
    if (password_check_verifier(pwd_key, verify) != 0) {
        unsigned char pwd_key_legacy[AES_KEY_LEN];
        if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                               salt, SALT_LEN, 100000,
                               EVP_sha256(), AES_KEY_LEN,
                               pwd_key_legacy) == 1 &&
            password_check_verifier(pwd_key_legacy, verify) == 0) {
            memcpy(pwd_key, pwd_key_legacy, AES_KEY_LEN);
            secure_wipe(pwd_key_legacy, AES_KEY_LEN);
            gui_post_log(log_target, "Password verified (legacy iterations)");
        } else {
            secure_wipe(pwd_key_legacy, AES_KEY_LEN);
            gui_post_log(log_target, "WRONG PASSWORD");
            goto cleanup;
        }
    }
    gui_post_log(log_target, "Password verified");

    /* RSA public key (skip) */
    if (p + 4 > len) goto cleanup;
    uint32_t pub_len = rd32(d + p); p += 4;
    if (pub_len > 8192 || p + pub_len > len) goto cleanup;
    p += pub_len;

    /* Encrypted RSA private key */
    if (p + AES_IV_LEN > len) goto cleanup;
    const unsigned char *rsa_iv = d + p; p += AES_IV_LEN;

    if (p + AES_TAG_LEN > len) goto cleanup;
    const unsigned char *rsa_tag = d + p; p += AES_TAG_LEN;

    if (p + 4 > len) goto cleanup;
    uint32_t erp_len = rd32(d + p); p += 4;
    if (erp_len > 16384 || p + erp_len > len) goto cleanup;
    const unsigned char *enc_rsa = d + p; p += erp_len;

    /* Decrypt RSA private key */
    gui_post_log(log_target, "Decrypting RSA private key...");
    rsa_priv = malloc(erp_len + 256);
    if (!rsa_priv) goto cleanup;

    if (decrypt_blob(pwd_key, rsa_iv, rsa_tag,
                     enc_rsa, erp_len,
                     rsa_priv, &rsa_priv_len) != 0) {
        gui_post_log(log_target,
            "RSA privkey decryption failed");
        goto cleanup;
    }

    /* Encrypted master key */
    if (p + 4 > len) goto cleanup;
    uint32_t emk_len = rd32(d + p); p += 4;
    if (emk_len > 1024 || p + emk_len > len) goto cleanup;
    const unsigned char *enc_mk = d + p; p += emk_len;

    /* Decrypt master key */
    gui_post_log(log_target, "Decrypting master key...");
    unsigned char mk_buf[512];
    size_t mk_buf_len = sizeof(mk_buf);

    if (rsa_decrypt_pem(rsa_priv, rsa_priv_len,
                        enc_mk, emk_len,
                        mk_buf, &mk_buf_len) != 0) {
        gui_post_log(log_target,
            "Master key decryption failed");
        goto cleanup;
    }

    if (mk_buf_len != MASTER_KEY_LEN) {
        gui_post_log(log_target,
            "Invalid master key length");
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }

    /* Filename */
    if (p + 4 > len) {
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }
    uint32_t fnl = rd32(d + p); p += 4;
    if (fnl > 1024 || p + fnl > len) {
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }
    char filename[1025];
    memcpy(filename, d + p, fnl);
    filename[fnl] = '\0';
    p += fnl;

        for (char *x = filename; *x; x++) {
        if (*x == '/' || *x == '\\' || *x == '\0')
            *x = '_';
    }

    if (filename[0] == '.')
        filename[0] = '_';

    if (fnl == 0) {
        strcpy(filename, "unnamed_file");
        fnl = 12;
    }

    /* File size */
    if (p + 8 > len) {
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }
    uint64_t file_size = rd64(d + p); p += 8;

    /* Chunk count */
    if (p + 4 > len) {
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }
    uint32_t chunk_count = rd32(d + p); p += 4;

    if (chunk_count > MAX_CHUNKS) {
        gui_post_log(log_target, "Chunk count too large: %u", chunk_count);
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }
    char sz[64];
    human_size((size_t)file_size, sz, sizeof(sz));
    gui_post_log(log_target,
        "Decrypting: %s (%s, %u chunks)",
        filename, sz, chunk_count);

    /* ── Open output file early ────────────────────────────── */

    mkdir_p(OUTPUT_DIR, 0700);
    snprintf(outpath, sizeof(outpath),
             "%s/%s", OUTPUT_DIR, filename);

    ofp = fopen(outpath, "wb");
    if (!ofp) {
        gui_post_log(log_target,
            "Cannot create: %s", outpath);
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }

    /* Pre-allocate file on disk */
    if (file_size > 0) {
        if (ftruncate(fileno(ofp), (off_t)file_size) != 0) {
            gui_post_log(log_target,
                "Failed to pre-allocate file: %s", strerror(errno));
            fclose(ofp);
            ofp = NULL;
            unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        fseek(ofp, 0, SEEK_SET);
    }

    /* 256KB write buffer for disk efficiency */
    wbuf = malloc(262144);
    if (wbuf)
        setvbuf(ofp, wbuf, _IOFBF, 262144);

    pt_buf = malloc(CHUNK_SIZE + 256);
    if (!pt_buf) {
        fclose(ofp); ofp = NULL;
        unlink(outpath);
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }

    /* ── Decrypt and write each chunk ──────────────────────── */

    struct timeval dec_start;
    gettimeofday(&dec_start, NULL);
    size_t bytes_written = 0;

    for (uint32_t i = 0; i < chunk_count; i++) {
        if (p + 4 > len) {
            gui_post_log(log_target,
                "Truncated at chunk %u", i);
            goto fail_file;
        }
        uint32_t gi = rd32(d + p); p += 4;

        if (p + 4 > len) goto fail_file;
        uint32_t ctlen = rd32(d + p); p += 4;

        if (ctlen > CHUNK_SIZE + 256) goto fail_file;

        if (p + AES_IV_LEN > len) goto fail_file;
        const unsigned char *iv = d + p;
        p += AES_IV_LEN;

        if (p + AES_TAG_LEN > len) goto fail_file;
        const unsigned char *tag = d + p;
        p += AES_TAG_LEN;

        if (p + ctlen > len) goto fail_file;
        const unsigned char *ct = d + p;
        p += ctlen;

        /* Derive chunk key */
        unsigned char ck[AES_KEY_LEN];
        if (derive_chunk_key(mk_buf, MASTER_KEY_LEN,
                             gi, ck, AES_KEY_LEN) != 0) {
            secure_wipe(ck, AES_KEY_LEN);
            goto fail_file;
        }

        size_t ptlen = 0;
        int rc = decrypt_chunk(ck, gi, iv, tag, ct,
                               ctlen, pt_buf, &ptlen);
        secure_wipe(ck, AES_KEY_LEN);

        if (rc != 0) {
            gui_post_log(log_target,
                "INTEGRITY FAILURE at chunk %u — ABORTING", i);
            goto fail_file;
        }

        /* Write immediately to disk */
        if (ptlen > 0) {
            size_t w = fwrite(pt_buf, 1, ptlen, ofp);
            if (w != ptlen) {
                gui_post_log(log_target,
                    "Disk write error at chunk %u", i);
                goto fail_file;
            }
            bytes_written += w;
        }

        /* Progress with speed */
        if (i == 0 || (i + 1) % 20 == 0 ||
            i + 1 == chunk_count) {

            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed =
                (double)(now.tv_sec - dec_start.tv_sec) +
                (double)(now.tv_usec - dec_start.tv_usec) / 1e6;

            if (elapsed > 0.1) {
                double speed =
                    (double)bytes_written / elapsed;
                char sp[64], bw[64];
                human_size((size_t)speed, sp, sizeof(sp));
                human_size(bytes_written, bw, sizeof(bw));

                gui_post_log(log_target,
                    "Decrypted %u/%u (%s) [%s/s]",
                    i + 1, chunk_count, bw, sp);
            }
        }

        gui_post_progress(log_target,
            (double)(i + 1) / chunk_count);
    }

    /* Flush and close */
    fflush(ofp);
    fsync(fileno(ofp));
    fclose(ofp);
    ofp = NULL;

    secure_wipe(mk_buf, mk_buf_len);

    /* Final stats */
    struct timeval dec_end;
    gettimeofday(&dec_end, NULL);
    double total_time =
        (double)(dec_end.tv_sec - dec_start.tv_sec) +
        (double)(dec_end.tv_usec - dec_start.tv_usec) / 1e6;

    double final_speed = (total_time > 0) ?
        (double)bytes_written / total_time : 0;
    char sp_final[64];
    human_size((size_t)final_speed, sp_final, sizeof(sp_final));

    gui_post_log(log_target,
        "═══════════════════════════════");
    gui_post_log(log_target,
        "File saved: %s", outpath);
    gui_post_log(log_target,
        "Decrypt speed: %s/s", sp_final);
    gui_post_log(log_target,
        "Transfer VERIFIED — integrity OK");
    gui_post_log(log_target,
        "═══════════════════════════════");

    gui_post_progress(log_target, 1.0);
    ret = 0;
    goto cleanup;

fail_file:
    if (ofp) { fclose(ofp); ofp = NULL; }
    unlink(outpath);
    secure_wipe(mk_buf, mk_buf_len);

cleanup:
    if (ofp) fclose(ofp);
    if (wbuf) free(wbuf);
    if (have_pwd_key) secure_wipe(pwd_key, AES_KEY_LEN);
    if (rsa_priv) {
        secure_wipe(rsa_priv, rsa_priv_len);
        free(rsa_priv);
    }
    if (pt_buf) free(pt_buf);
    return ret;
}

/* ──────────────────────────────────────────────────────────────
 * PARSE UPLOAD METADATA (parallel mode)
 * ────────────────────────────────────────────────────────────── */

int protocol_parse_upload_metadata(
    const uint8_t *data, size_t len,
    char *file_id_out,
    const char *external_file_id,
    int log_target)
{
    size_t p = 0;

    if (p + 4 > len) return -1;
    if (memcmp(data + p, PROTO_MAGIC_UPLOAD, 4) != 0) {
        gui_post_log(log_target,
            "Invalid upload-parallel magic");
        return -1;
    }
    p += 4;

    if (p + 4 > len) return -1;
    uint32_t version = rd32(data + p); p += 4;
    if (version != PROTO_VERSION) {
        gui_post_log(log_target,
            "Unsupported version: %u", version);
        return -1;
    }

    /* ── FILE ID: use external if provided ─────
       
       When called from /upload-parallel, the
       client provides its file_id (which is
       SHA256 of the FULL payload including chunks).
       
       We MUST use this, because the client
       already uploaded chunks to sub-servers
       under this file_id.
       
       If we compute our own SHA256 from the
       metadata-only bytes, we get a DIFFERENT
       hash and the download will fail with 403.
       ──────────────────────────────────────────── */

    if (external_file_id &&
        external_file_id[0] != '\0') {
        strncpy(file_id_out, external_file_id,
                FILE_ID_HEX_LEN);
        file_id_out[FILE_ID_HEX_LEN] = '\0';

        gui_post_log(log_target,
            "Using client file ID: %.16s...",
            file_id_out);
    } else {
        /* Fallback: compute from data
           (only correct if data = full payload) */
        if (compute_sha256_hex(data, len,
                               file_id_out) != 0)
            return -1;
    }

    gui_post_log(log_target,
        "Parallel upload ID: %.16s...",
        file_id_out);

    pthread_mutex_lock(&app.stored_mutex);
        if (app.stored_file_count >= MAX_STORED_FILES ||
        ensure_stored_capacity() != 0) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target, "Storage full");
        return -1;
    }

    /* Check for duplicate file_id */
    for (int i = 0;
         i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id_out) == 0) {
            pthread_mutex_unlock(
                &app.stored_mutex);
            gui_post_log(log_target,
                "File already exists: %.16s...",
                file_id_out);
            return 0; /* not an error */
        }
    }

    StoredFileMeta *meta =
        &app.stored_files[app.stored_file_count];
    memset(meta, 0, sizeof(*meta));
    strncpy(meta->file_id, file_id_out,
            FILE_ID_HEX_LEN);

    if (p + SALT_LEN > len) goto fail_unlock;
    memcpy(meta->password_salt, data + p, SALT_LEN);
    p += SALT_LEN;

    if (p + HASH_LEN > len) goto fail_unlock;
    memcpy(meta->password_verify, data + p, HASH_LEN);
    p += HASH_LEN;

    if (p + 4 > len) goto fail_unlock;
    uint32_t pub_len = rd32(data + p); p += 4;
    if (pub_len > sizeof(meta->rsa_pub_pem) ||
        p + pub_len > len)
        goto fail_unlock;
    memcpy(meta->rsa_pub_pem, data + p, pub_len);
    meta->rsa_pub_len = pub_len;
    p += pub_len;

    if (p + AES_IV_LEN > len) goto fail_unlock;
    memcpy(meta->rsa_priv_iv, data + p, AES_IV_LEN);
    p += AES_IV_LEN;

    if (p + AES_TAG_LEN > len) goto fail_unlock;
    memcpy(meta->rsa_priv_tag, data + p, AES_TAG_LEN);
    p += AES_TAG_LEN;

    if (p + 4 > len) goto fail_unlock;
    uint32_t erp_len = rd32(data + p); p += 4;
    if (erp_len > sizeof(meta->enc_rsa_priv) ||
        p + erp_len > len)
        goto fail_unlock;
    memcpy(meta->enc_rsa_priv, data + p, erp_len);
    meta->erp_len = erp_len;
    p += erp_len;

    if (p + 4 > len) goto fail_unlock;
    uint32_t emk_len = rd32(data + p); p += 4;
    if (emk_len > sizeof(meta->enc_master_key) ||
        p + emk_len > len)
        goto fail_unlock;
    memcpy(meta->enc_master_key, data + p, emk_len);
    meta->emk_len = emk_len;
    p += emk_len;

    if (p + 4 > len) goto fail_unlock;
    uint32_t fnl = rd32(data + p); p += 4;
    if (fnl > sizeof(meta->original_name) - 1 ||
        p + fnl > len)
        goto fail_unlock;
    memcpy(meta->original_name, data + p, fnl);
    meta->original_name[fnl] = '\0';
    p += fnl;

    for (char *x = meta->original_name; *x; x++)
        if (*x == '/' || *x == '\\') *x = '_';

    if (p + 8 > len) goto fail_unlock;
    meta->original_size = (size_t)rd64(data + p);
    p += 8;

    if (p + 4 > len) goto fail_unlock;
    meta->chunk_count = rd32(data + p);
    p += 4;

    if (meta->chunk_count > MAX_CHUNKS) goto fail_unlock;

    meta->upload_time = time(NULL);
    meta->distributed = 2;

    app.stored_file_count++;
    app.upload_count++;

    StoredFileMeta meta_copy;
    memcpy(&meta_copy, meta, sizeof(meta_copy));
    pthread_mutex_unlock(&app.stored_mutex);

    storage_save_meta(&meta_copy, log_target);

    char sz[64];
    human_size(meta_copy.original_size, sz, sizeof(sz));
    gui_post_log(log_target,
        "\xE2\x9C\x93 Parallel metadata stored: "
        "%s [%s] %u chunks (ID: %.16s...)",
        meta_copy.original_name, sz,
        meta_copy.chunk_count, file_id_out);

    return 0;

fail_unlock:
    pthread_mutex_unlock(&app.stored_mutex);
    gui_post_log(log_target,
        "Malformed parallel upload metadata");
    return -1;
}

/* ──────────────────────────────────────────────────────────────
 * BUILD DOWNLOAD METADATA (parallel mode)
 * ────────────────────────────────────────────────────────────── */

int protocol_build_download_metadata(
    const char *file_id, const char *password,
    Buf *out, int log_target)
{
    StoredFileMeta *meta = NULL;
    pthread_mutex_lock(&app.stored_mutex);

    for (int i = 0; i < app.stored_file_count; i++) {
        if (strcmp(app.stored_files[i].file_id,
                  file_id) == 0) {
            meta = &app.stored_files[i];
            break;
        }
    }

    if (!meta) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target,
            "File not found: %.16s...", file_id);
        return -1;
    }

    StoredFileMeta mcopy;
    memcpy(&mcopy, meta, sizeof(mcopy));
    pthread_mutex_unlock(&app.stored_mutex);

    unsigned char pwd_key[AES_KEY_LEN];
    if (password_derive_key(password,
                            mcopy.password_salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0) {
        gui_post_log(log_target, "Key derivation failed");
        return -1;
    }

    if (password_check_verifier(pwd_key,
                                mcopy.password_verify) != 0) {
        gui_post_log(log_target,
            "WRONG PASSWORD for file %.16s...", file_id);
        secure_wipe(pwd_key, AES_KEY_LEN);
        return -1;
    }

    secure_wipe(pwd_key, AES_KEY_LEN);

    gui_post_log(log_target,
        "Password verified for %.16s... (parallel)",
        file_id);

    buf_add(out, PROTO_MAGIC_DOWNLOAD, 4);
    buf_u32(out, PROTO_VERSION);
    buf_add(out, mcopy.password_salt, SALT_LEN);
    buf_add(out, mcopy.password_verify, HASH_LEN);

    buf_u32(out, (uint32_t)mcopy.rsa_pub_len);
    buf_add(out, mcopy.rsa_pub_pem, mcopy.rsa_pub_len);

    buf_add(out, mcopy.rsa_priv_iv, AES_IV_LEN);
    buf_add(out, mcopy.rsa_priv_tag, AES_TAG_LEN);
    buf_u32(out, (uint32_t)mcopy.erp_len);
    buf_add(out, mcopy.enc_rsa_priv, mcopy.erp_len);

    buf_u32(out, (uint32_t)mcopy.emk_len);
    buf_add(out, mcopy.enc_master_key, mcopy.emk_len);

    uint32_t fnl = (uint32_t)strlen(mcopy.original_name);
    buf_u32(out, fnl);
    buf_add(out, mcopy.original_name, fnl);

    buf_u64(out, (uint64_t)mcopy.original_size);
    buf_u32(out, mcopy.chunk_count);

    char sz[64];
    human_size(out->len, sz, sizeof(sz));
    gui_post_log(log_target,
        "Download metadata: %s (parallel, "
        "%u chunks on sub-servers)",
        sz, mcopy.chunk_count);

    return 0;
}