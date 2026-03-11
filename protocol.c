#include "protocol.h"
#include "storage.h"
#include "gui_helpers.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

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

    /* Sensitive material */
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

    /* Step 1: Generate master key */
    if (secure_random(master_key, MASTER_KEY_LEN) != 0) {
        gui_post_log(log_target, "CSPRNG failure");
        goto cleanup;
    }

    /* Step 2: Derive password key */
    if (secure_random(pwd_salt, SALT_LEN) != 0) goto cleanup;

    if (password_derive_key(password, pwd_salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0) {
        gui_post_log(log_target, "Key derivation failed");
        goto cleanup;
    }

    /* Step 3: Create password verifier */
    if (password_make_verifier(pwd_key, pwd_verify) != 0)
        goto cleanup;

    /* Step 4: Generate per-file RSA keypair */
    gui_post_log(log_target, "Generating RSA-2048 keypair...");
    if (gen_rsa_keys_to_pem(rsa_pub, &rsa_pub_len,
                            rsa_priv, &rsa_priv_len) != 0) {
        gui_post_log(log_target, "RSA keygen failed");
        goto cleanup;
    }
    have_keys = 1;

    /* Step 5: Encrypt RSA private key with password-derived key */
    if (encrypt_blob(pwd_key,
                     rsa_priv, rsa_priv_len,
                     rsa_priv_iv, enc_rsa_priv,
                     &enc_rsa_priv_len,
                     rsa_priv_tag) != 0) {
        gui_post_log(log_target, "RSA privkey encryption failed");
        goto cleanup;
    }

    /* Step 6: Encrypt master key with RSA public key */
    if (rsa_encrypt_pem(rsa_pub, rsa_pub_len,
                        master_key, MASTER_KEY_LEN,
                        enc_master, &enc_master_len) != 0) {
        gui_post_log(log_target, "Master key encryption failed");
        goto cleanup;
    }

    /* Step 7: Open source file */
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

    /* Step 8: Build header */
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

    /* Step 9: Encrypt chunks */
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

        /* Derive unique per-chunk key */
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

    /* Step 10: Compute file ID */
    if (compute_sha256_hex(payload->data, payload->len,
                           file_id_out) != 0) {
        gui_post_log(log_target, "Hash computation failed");
        goto cleanup;
    }

    human_size(payload->len, sz, sizeof(sz));
    gui_post_log(log_target, "Payload ready: %s", sz);
    gui_post_log(log_target, "File ID: %.16s...",
                 file_id_out);

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
 * PARSE UPLOAD — called by server when receiving upload
 * ────────────────────────────────────────────────────────────── */

int protocol_parse_upload(const unsigned char *d, size_t len,
                          char *file_id_out,
                          int log_target)
{
    size_t p = 0;

    /* Verify magic */
    if (p + 4 > len) return -1;
    if (memcmp(d + p, PROTO_MAGIC_UPLOAD, 4) != 0) {
        gui_post_log(log_target, "Invalid upload magic");
        return -1;
    }
    p += 4;

    /* Version */
    if (p + 4 > len) return -1;
    uint32_t version = rd32(d + p); p += 4;
    if (version != PROTO_VERSION) {
        gui_post_log(log_target,
            "Unsupported version: %u", version);
        return -1;
    }

    /* Compute file ID from raw payload */
    if (compute_sha256_hex(d, len, file_id_out) != 0)
        return -1;

    gui_post_log(log_target, "Upload file ID: %.16s...",
                 file_id_out);

    /* Allocate stored file metadata */
    pthread_mutex_lock(&app.stored_mutex);
    if (app.stored_file_count >= MAX_STORED_FILES) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target, "Storage full");
        return -1;
    }

    StoredFileMeta *meta =
        &app.stored_files[app.stored_file_count];
    memset(meta, 0, sizeof(*meta));
    strncpy(meta->file_id, file_id_out, FILE_ID_HEX_LEN);

    /* Password salt */
    if (p + SALT_LEN > len) goto fail_unlock;
    memcpy(meta->password_salt, d + p, SALT_LEN);
    p += SALT_LEN;

    /* Password verify */
    if (p + HASH_LEN > len) goto fail_unlock;
    memcpy(meta->password_verify, d + p, HASH_LEN);
    p += HASH_LEN;

    /* RSA public key PEM */
    if (p + 4 > len) goto fail_unlock;
    uint32_t pub_len = rd32(d + p); p += 4;
    if (pub_len > sizeof(meta->rsa_pub_pem) ||
        p + pub_len > len)
        goto fail_unlock;
    memcpy(meta->rsa_pub_pem, d + p, pub_len);
    meta->rsa_pub_len = pub_len;
    p += pub_len;

    /* Encrypted RSA private key */
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

    /* Encrypted master key */
    if (p + 4 > len) goto fail_unlock;
    uint32_t emk_len = rd32(d + p); p += 4;
    if (emk_len > sizeof(meta->enc_master_key) ||
        p + emk_len > len)
        goto fail_unlock;
    memcpy(meta->enc_master_key, d + p, emk_len);
    meta->emk_len = emk_len;
    p += emk_len;

    /* Filename */
    if (p + 4 > len) goto fail_unlock;
    uint32_t fnl = rd32(d + p); p += 4;
    if (fnl > sizeof(meta->original_name) - 1 ||
        p + fnl > len)
        goto fail_unlock;
    memcpy(meta->original_name, d + p, fnl);
    meta->original_name[fnl] = '\0';
    p += fnl;

    /* Sanitize filename */
    for (char *x = meta->original_name; *x; x++)
        if (*x == '/' || *x == '\\') *x = '_';

    /* File size */
    if (p + 8 > len) goto fail_unlock;
    meta->original_size = (size_t)rd64(d + p);
    p += 8;

    /* Chunk count */
    if (p + 4 > len) goto fail_unlock;
    meta->chunk_count = rd32(d + p);
    p += 4;

    if (meta->chunk_count > MAX_CHUNKS) goto fail_unlock;

    meta->upload_time = time(NULL);

    char sz_str[64];
    human_size(meta->original_size, sz_str, sizeof(sz_str));
    gui_post_log(log_target, "Storing: %s (%s, %u chunks)",
                 meta->original_name, sz_str,
                 meta->chunk_count);

    pthread_mutex_unlock(&app.stored_mutex);

    /* Store each chunk to disk / sub-servers */
    for (uint32_t i = 0; i < meta->chunk_count; i++) {
        if (p + 4 > len) return -1;
        uint32_t gi = rd32(d + p); p += 4;

        if (p + 4 > len) return -1;
        uint32_t ctlen = rd32(d + p); p += 4;

        if (p + AES_IV_LEN + AES_TAG_LEN + ctlen > len)
            return -1;

        const unsigned char *chunk_data = d + p;
        size_t chunk_total =
            AES_IV_LEN + AES_TAG_LEN + ctlen;
        p += chunk_total;

        Buf chunk_buf;
        buf_init(&chunk_buf);
        buf_u32(&chunk_buf, gi);
        buf_u32(&chunk_buf, ctlen);
        buf_add(&chunk_buf, chunk_data, chunk_total);

        int sub_idx = storage_store_chunk(
            file_id_out, i,
            chunk_buf.data, chunk_buf.len,
            log_target);

        pthread_mutex_lock(&app.stored_mutex);
        meta->chunk_locations[i] = sub_idx;
        pthread_mutex_unlock(&app.stored_mutex);

        buf_free(&chunk_buf);

        gui_post_progress(log_target,
            (double)(i + 1) / meta->chunk_count);
    }

    pthread_mutex_lock(&app.stored_mutex);
    meta->distributed =
        (app.num_sub_servers > 0) ? 1 : 0;
    app.stored_file_count++;
    app.upload_count++;
    pthread_mutex_unlock(&app.stored_mutex);

    /* Save metadata to disk */
    storage_save_meta(meta, log_target);

    gui_post_log(log_target, "Upload stored successfully");
    gui_post_log(log_target, "File ID: %s", file_id_out);

    return 0;

fail_unlock:
    pthread_mutex_unlock(&app.stored_mutex);
    gui_post_log(log_target, "Malformed upload payload");
    return -1;
}

/* ──────────────────────────────────────────────────────────────
 * BUILD DOWNLOAD RESPONSE
 * ────────────────────────────────────────────────────────────── */

int protocol_build_download(const char *file_id,
                            const char *password,
                            Buf *response,
                            int log_target)
{
    /* Find stored file */
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

    /* Copy metadata locally to release lock */
    StoredFileMeta mcopy;
    memcpy(&mcopy, meta, sizeof(mcopy));
    pthread_mutex_unlock(&app.stored_mutex);

    /* Verify password */
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

    /* Build download response header */
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

    gui_post_log(log_target, "Collecting %u chunks...",
                 mcopy.chunk_count);

    /* Collect chunks from storage / sub-servers */
    for (uint32_t i = 0; i < mcopy.chunk_count; i++) {
        Buf chunk_buf;
        buf_init(&chunk_buf);

        int rc = storage_retrieve_chunk(
            file_id, i,
            mcopy.chunk_locations[i],
            &chunk_buf,
            log_target);

        if (rc != 0) {
            gui_post_log(log_target,
                "Failed to retrieve chunk %u", i);
            buf_free(&chunk_buf);
            secure_wipe(pwd_key, AES_KEY_LEN);
            return -1;
        }

        buf_add(response, chunk_buf.data, chunk_buf.len);
        buf_free(&chunk_buf);

        gui_post_progress(log_target,
            (double)(i + 1) / mcopy.chunk_count);
    }

    secure_wipe(pwd_key, AES_KEY_LEN);

    char sz[64];
    human_size(response->len, sz, sizeof(sz));
    gui_post_log(log_target, "Download response: %s", sz);
    app.download_count++;

    return 0;
}

/* ──────────────────────────────────────────────────────────────
 * PARSE DOWNLOAD RESPONSE — called by receiver
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
    int have_pwd_key = 0;

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
        gui_post_log(log_target, "WRONG PASSWORD");
        goto cleanup;
    }
    gui_post_log(log_target, "Password verified");

    /* RSA public key (skip) */
    if (p + 4 > len) goto cleanup;
    uint32_t pub_len = rd32(d + p); p += 4;
    if (p + pub_len > len) goto cleanup;
    p += pub_len;

    /* Encrypted RSA private key */
    if (p + AES_IV_LEN > len) goto cleanup;
    const unsigned char *rsa_iv = d + p; p += AES_IV_LEN;

    if (p + AES_TAG_LEN > len) goto cleanup;
    const unsigned char *rsa_tag = d + p; p += AES_TAG_LEN;

    if (p + 4 > len) goto cleanup;
    uint32_t erp_len = rd32(d + p); p += 4;
    if (p + erp_len > len) goto cleanup;
    const unsigned char *enc_rsa = d + p; p += erp_len;

    /* Decrypt RSA private key */
    gui_post_log(log_target,
        "Decrypting RSA private key...");
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
    if (p + emk_len > len) goto cleanup;
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
        secure_wipe(mk_buf, mk_buf_len); goto cleanup;
    }
    uint32_t fnl = rd32(d + p); p += 4;
    if (fnl > 1024 || p + fnl > len) {
        secure_wipe(mk_buf, mk_buf_len); goto cleanup;
    }
    char filename[1025];
    memcpy(filename, d + p, fnl);
    filename[fnl] = '\0';
    p += fnl;

    /* Sanitize */
    for (char *x = filename; *x; x++)
        if (*x == '/' || *x == '\\') *x = '_';

    /* File size */
    if (p + 8 > len) {
        secure_wipe(mk_buf, mk_buf_len); goto cleanup;
    }
    uint64_t file_size = rd64(d + p); p += 8;

    /* Chunk count */
    if (p + 4 > len) {
        secure_wipe(mk_buf, mk_buf_len); goto cleanup;
    }
    uint32_t chunk_count = rd32(d + p); p += 4;

    char sz[64];
    human_size((size_t)file_size, sz, sizeof(sz));
    gui_post_log(log_target,
        "Decrypting: %s (%s, %u chunks)",
        filename, sz, chunk_count);

    /* Create output directory */
    mkdir_p(OUTPUT_DIR, 0700);

    char outpath[2048];
    snprintf(outpath, sizeof(outpath), "%s/%s",
             OUTPUT_DIR, filename);

    FILE *ofp = fopen(outpath, "wb");
    if (!ofp) {
        gui_post_log(log_target,
            "Cannot create: %s", outpath);
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }

    pt_buf = malloc(CHUNK_SIZE + 256);
    if (!pt_buf) {
        fclose(ofp);
        secure_wipe(mk_buf, mk_buf_len);
        goto cleanup;
    }

    /* Decrypt each chunk */
    for (uint32_t i = 0; i < chunk_count; i++) {
        if (p + 4 > len) {
            gui_post_log(log_target,
                "Truncated at chunk %u", i);
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        uint32_t gi = rd32(d + p); p += 4;

        if (p + 4 > len) {
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        uint32_t ctlen = rd32(d + p); p += 4;

        if (p + AES_IV_LEN > len) {
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        const unsigned char *iv = d + p;
        p += AES_IV_LEN;

        if (p + AES_TAG_LEN > len) {
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        const unsigned char *tag = d + p;
        p += AES_TAG_LEN;

        if (p + ctlen > len) {
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }
        const unsigned char *ct = d + p;
        p += ctlen;

        /* Derive chunk key */
        unsigned char ck[AES_KEY_LEN];
        if (derive_chunk_key(mk_buf, MASTER_KEY_LEN,
                             gi, ck, AES_KEY_LEN) != 0) {
            secure_wipe(ck, AES_KEY_LEN);
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }

        size_t ptlen = 0;
        int rc = decrypt_chunk(ck, gi, iv, tag, ct,
                               ctlen, pt_buf, &ptlen);
        secure_wipe(ck, AES_KEY_LEN);

        if (rc != 0) {
            gui_post_log(log_target,
                "INTEGRITY FAILURE at chunk %u "
                "— aborting", i);
            fclose(ofp); unlink(outpath);
            secure_wipe(mk_buf, mk_buf_len);
            goto cleanup;
        }

        if (ptlen > 0)
            fwrite(pt_buf, 1, ptlen, ofp);

        gui_post_progress(log_target,
            (double)(i + 1) / chunk_count);
    }

    fclose(ofp);
    secure_wipe(mk_buf, mk_buf_len);

    gui_post_log(log_target, "File saved: %s", outpath);
    gui_post_log(log_target,
        "Transfer complete — verified");
    gui_post_progress(log_target, 1.0);
    ret = 0;

cleanup:
    if (have_pwd_key) secure_wipe(pwd_key, AES_KEY_LEN);
    if (rsa_priv) {
        secure_wipe(rsa_priv, rsa_priv_len);
        free(rsa_priv);
    }
    if (pt_buf) free(pt_buf);
    return ret;
}

/* ──────────────────────────────────────────────────────────────
 * PARSE UPLOAD METADATA (parallel mode — no chunk data)
 *
 * Same header format as protocol_parse_upload but stops
 * after header fields. Chunks uploaded to sub-servers.
 * ────────────────────────────────────────────────────────────── */

int protocol_parse_upload_metadata(
    const uint8_t *data, size_t len,
    char *file_id_out, int log_target)
{
    size_t p = 0;

    /* Magic */
    if (p + 4 > len) return -1;
    if (memcmp(data + p, PROTO_MAGIC_UPLOAD, 4) != 0) {
        gui_post_log(log_target,
            "Invalid upload-parallel magic");
        return -1;
    }
    p += 4;

    /* Version */
    if (p + 4 > len) return -1;
    uint32_t version = rd32(data + p); p += 4;
    if (version != PROTO_VERSION) {
        gui_post_log(log_target,
            "Unsupported version: %u", version);
        return -1;
    }

    /* Compute file ID */
    if (compute_sha256_hex(data, len, file_id_out) != 0)
        return -1;

    gui_post_log(log_target,
        "Parallel upload ID: %.16s...", file_id_out);

    /* Allocate stored file slot */
    pthread_mutex_lock(&app.stored_mutex);
    if (app.stored_file_count >= MAX_STORED_FILES) {
        pthread_mutex_unlock(&app.stored_mutex);
        gui_post_log(log_target, "Storage full");
        return -1;
    }

    StoredFileMeta *meta =
        &app.stored_files[app.stored_file_count];
    memset(meta, 0, sizeof(*meta));
    strncpy(meta->file_id, file_id_out,
            FILE_ID_HEX_LEN);

    /* Password salt */
    if (p + SALT_LEN > len) goto fail_unlock;
    memcpy(meta->password_salt, data + p, SALT_LEN);
    p += SALT_LEN;

    /* Password verify */
    if (p + HASH_LEN > len) goto fail_unlock;
    memcpy(meta->password_verify, data + p, HASH_LEN);
    p += HASH_LEN;

    /* RSA public key PEM */
    if (p + 4 > len) goto fail_unlock;
    uint32_t pub_len = rd32(data + p); p += 4;
    if (pub_len > sizeof(meta->rsa_pub_pem) ||
        p + pub_len > len)
        goto fail_unlock;
    memcpy(meta->rsa_pub_pem, data + p, pub_len);
    meta->rsa_pub_len = pub_len;
    p += pub_len;

    /* Encrypted RSA private key */
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

    /* Encrypted master key */
    if (p + 4 > len) goto fail_unlock;
    uint32_t emk_len = rd32(data + p); p += 4;
    if (emk_len > sizeof(meta->enc_master_key) ||
        p + emk_len > len)
        goto fail_unlock;
    memcpy(meta->enc_master_key, data + p, emk_len);
    meta->emk_len = emk_len;
    p += emk_len;

    /* Filename */
    if (p + 4 > len) goto fail_unlock;
    uint32_t fnl = rd32(data + p); p += 4;
    if (fnl > sizeof(meta->original_name) - 1 ||
        p + fnl > len)
        goto fail_unlock;
    memcpy(meta->original_name, data + p, fnl);
    meta->original_name[fnl] = '\0';
    p += fnl;

    /* Sanitize filename */
    for (char *x = meta->original_name; *x; x++)
        if (*x == '/' || *x == '\\') *x = '_';

    /* File size */
    if (p + 8 > len) goto fail_unlock;
    meta->original_size = (size_t)rd64(data + p);
    p += 8;

    /* Chunk count */
    if (p + 4 > len) goto fail_unlock;
    meta->chunk_count = rd32(data + p);
    p += 4;

    if (meta->chunk_count > MAX_CHUNKS) goto fail_unlock;

    meta->upload_time = time(NULL);
    meta->distributed = 2;  /* 2 = parallel mode */

    /* Commit */
    app.stored_file_count++;
    app.upload_count++;
    pthread_mutex_unlock(&app.stored_mutex);

    /* Save metadata to disk */
    storage_save_meta(meta, log_target);

    char sz[64];
    human_size(meta->original_size, sz, sizeof(sz));
    gui_post_log(log_target,
        "\xE2\x9C\x93 Parallel metadata stored: "
        "%s [%s] %u chunks",
        meta->original_name, sz, meta->chunk_count);

    return 0;

fail_unlock:
    pthread_mutex_unlock(&app.stored_mutex);
    gui_post_log(log_target,
        "Malformed parallel upload metadata");
    return -1;
}

/* ──────────────────────────────────────────────────────────────
 * BUILD DOWNLOAD METADATA (parallel mode — no chunk data)
 *
 * Same as protocol_build_download but does NOT append
 * chunk data. Client fetches chunks from sub-servers.
 * ────────────────────────────────────────────────────────────── */

int protocol_build_download_metadata(
    const char *file_id, const char *password,
    Buf *out, int log_target)
{
    /* Find stored file */
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

    /* Copy metadata locally */
    StoredFileMeta mcopy;
    memcpy(&mcopy, meta, sizeof(mcopy));
    pthread_mutex_unlock(&app.stored_mutex);

    /* Verify password */
    unsigned char pwd_key[AES_KEY_LEN];
    if (password_derive_key(password,
                            mcopy.password_salt, SALT_LEN,
                            pwd_key, AES_KEY_LEN) != 0) {
        gui_post_log(log_target,
            "Key derivation failed");
        return -1;
    }

    if (password_check_verifier(pwd_key,
                                mcopy.password_verify) != 0) {
        gui_post_log(log_target,
            "WRONG PASSWORD for file %.16s...",
            file_id);
        secure_wipe(pwd_key, AES_KEY_LEN);
        return -1;
    }

    secure_wipe(pwd_key, AES_KEY_LEN);

    gui_post_log(log_target,
        "Password verified for %.16s... (parallel)",
        file_id);

    /* Build download header (same format as normal) */
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

    /* NO CHUNKS — client fetches from sub-servers */

    char sz[64];
    human_size(out->len, sz, sizeof(sz));
    gui_post_log(log_target,
        "Download metadata: %s (parallel, "
        "%u chunks on sub-servers)",
        sz, mcopy.chunk_count);

    return 0;
}