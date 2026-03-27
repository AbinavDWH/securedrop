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

#include "crypto.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <fcntl.h>

/* ── Error logging ─────────────────────────────────────────── */

void log_ssl_errors(const char *ctx)
{
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, "[SSL %s] %s\n", ctx, buf);
    }
}

/* ── Secure memory ─────────────────────────────────────────── */

int secure_random(unsigned char *buf, size_t len)
{
    if (RAND_bytes(buf, (int)len) != 1) {
        log_ssl_errors("RAND_bytes");
        return -1;
    }
    return 0;
}

void secure_wipe(void *buf, size_t len)
{
    OPENSSL_cleanse(buf, len);
}

/* ── HKDF-SHA256 chunk key derivation ──────────────────────── */

int derive_chunk_key(const unsigned char *master, size_t mlen,
                     uint32_t chunk_idx,
                     unsigned char *out, size_t olen)
{
    int ret = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) { log_ssl_errors("HKDF-fetch"); return -1; }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return -1;

    uint32_t idx_be = htonl(chunk_idx);
    char salt_str[] = "securedrop-chunk-v5";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest",
                                         (char *)"SHA256", 0),
        OSSL_PARAM_construct_octet_string("key",
                                         (void *)master, mlen),
        OSSL_PARAM_construct_octet_string("salt",
                                         salt_str,
                                         strlen(salt_str)),
        OSSL_PARAM_construct_octet_string("info",
                                         &idx_be,
                                         sizeof(idx_be)),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, out, olen, params) > 0)
        ret = 0;
    else
        log_ssl_errors("HKDF-derive");

    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* ── AES-256-GCM chunk encryption ──────────────────────────── */

int encrypt_chunk(const unsigned char *key, uint32_t chunk_idx,
                  const unsigned char *pt, size_t ptlen,
                  unsigned char *iv_out,
                  unsigned char *ct_out, size_t *ctlen_out,
                  unsigned char *tag_out)
{
    int ret = -1;

    if (secure_random(iv_out, AES_IV_LEN) != 0)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outl = 0, tmpl = 0;
    uint32_t idx_be = htonl(chunk_idx);

    /* Init cipher */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN, NULL) != 1)
        goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv_out) != 1)
        goto end;

    /* AAD: chunk index in network byte order */
    if (EVP_EncryptUpdate(ctx, NULL, &outl,
                          (unsigned char *)&idx_be, 4) != 1)
        goto end;

    /* Encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ct_out, &outl,
                          pt, (int)ptlen) != 1)
        goto end;
    *ctlen_out = (size_t)outl;

    if (EVP_EncryptFinal_ex(ctx, ct_out + outl, &tmpl) != 1)
        goto end;
    *ctlen_out += (size_t)tmpl;

    /* Extract tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            AES_TAG_LEN, tag_out) != 1)
        goto end;

    ret = 0;

end:
    if (ret != 0) log_ssl_errors("encrypt_chunk");
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── AES-256-GCM chunk decryption ──────────────────────────── */

int decrypt_chunk(const unsigned char *key, uint32_t chunk_idx,
                  const unsigned char *iv,
                  const unsigned char *tag,
                  const unsigned char *ct, size_t ctlen,
                  unsigned char *pt_out, size_t *ptlen_out)
{
    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outl = 0, tmpl = 0;
    uint32_t idx_be = htonl(chunk_idx);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN, NULL) != 1)
        goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto end;

    /* AAD */
    if (EVP_DecryptUpdate(ctx, NULL, &outl,
                          (unsigned char *)&idx_be, 4) != 1)
        goto end;

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, pt_out, &outl,
                          ct, (int)ctlen) != 1)
        goto end;
    *ptlen_out = (size_t)outl;

    /* Set expected tag before final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            AES_TAG_LEN,
                            (void *)tag) != 1)
        goto end;

    /* Final — fails if tag mismatch (integrity) */
    if (EVP_DecryptFinal_ex(ctx, pt_out + outl, &tmpl) != 1)
        goto end;
    *ptlen_out += (size_t)tmpl;

    ret = 0;

end:
    if (ret != 0) log_ssl_errors("decrypt_chunk");
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── AES-256-GCM blob encrypt (no AAD) ─────────────────────── */

int encrypt_blob(const unsigned char *key,
                 const unsigned char *pt, size_t ptlen,
                 unsigned char *iv_out,
                 unsigned char *ct_out, size_t *ctlen_out,
                 unsigned char *tag_out)
{
    if (secure_random(iv_out, AES_IV_LEN) != 0)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, outl = 0, tmpl = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN, NULL) != 1)
        goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv_out) != 1)
        goto end;
    if (EVP_EncryptUpdate(ctx, ct_out, &outl,
                          pt, (int)ptlen) != 1)
        goto end;
    *ctlen_out = (size_t)outl;
    if (EVP_EncryptFinal_ex(ctx, ct_out + outl, &tmpl) != 1)
        goto end;
    *ctlen_out += (size_t)tmpl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            AES_TAG_LEN, tag_out) != 1)
        goto end;
    ret = 0;

end:
    if (ret) log_ssl_errors("encrypt_blob");
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_blob(const unsigned char *key,
                 const unsigned char *iv,
                 const unsigned char *tag,
                 const unsigned char *ct, size_t ctlen,
                 unsigned char *pt_out, size_t *ptlen_out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1, outl = 0, tmpl = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_IV_LEN, NULL) != 1)
        goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto end;
    if (EVP_DecryptUpdate(ctx, pt_out, &outl,
                          ct, (int)ctlen) != 1)
        goto end;
    *ptlen_out = (size_t)outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            AES_TAG_LEN, (void *)tag) != 1)
        goto end;
    if (EVP_DecryptFinal_ex(ctx, pt_out + outl, &tmpl) != 1)
        goto end;
    *ptlen_out += (size_t)tmpl;
    ret = 0;

end:
    if (ret) log_ssl_errors("decrypt_blob");
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── RSA-4096 key generation to PEM buffers ────────────────── */

int gen_rsa_keys_to_pem(unsigned char *pub_pem, size_t *pub_len,
                        unsigned char *priv_pem, size_t *priv_len)
{
    int ret = -1;
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0)
        goto done;
    if (EVP_PKEY_keygen(ctx, &pk) <= 0) goto done;

    /* Write public key to memory BIO */
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) goto done;
        if (PEM_write_bio_PUBKEY(bio, pk) != 1) {
            BIO_free(bio); goto done;
        }
        long plen = BIO_get_mem_data(bio, NULL);
        char *pdata = NULL;
        plen = BIO_get_mem_data(bio, &pdata);
        if ((size_t)plen > *pub_len - 1) { BIO_free(bio); goto done; }
        memcpy(pub_pem, pdata, (size_t)plen);
        pub_pem[plen] = '\0';
        *pub_len = (size_t)plen;
        BIO_free(bio);
    }

    /* Write private key to memory BIO */
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) goto done;
        if (PEM_write_bio_PrivateKey(bio, pk, NULL, NULL, 0,
                                     NULL, NULL) != 1) {
            BIO_free(bio); goto done;
        }
        char *pdata = NULL;
        long plen = BIO_get_mem_data(bio, &pdata);
        if ((size_t)plen > *priv_len - 1) { BIO_free(bio); goto done; }
        memcpy(priv_pem, pdata, (size_t)plen);
        priv_pem[plen] = '\0';
        *priv_len = (size_t)plen;
        BIO_free(bio);
    }

    ret = 0;

done:
    if (ret) log_ssl_errors("gen_rsa_keys_to_pem");
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int gen_rsa_keys_to_file(const char *pub_file, const char *priv_file)
{
    int ret = -1;
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0)
        goto done;
    if (EVP_PKEY_keygen(ctx, &pk) <= 0) goto done;

    {
        int fd = open(priv_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) goto done;
        FILE *fp = fdopen(fd, "w");
        if (!fp) {
            close(fd);
            goto done;
        }
        if (PEM_write_PrivateKey(fp, pk, NULL, NULL, 0, NULL, NULL) != 1) {
            fclose(fp);
            goto done;
        }
        fclose(fp);
    }
    {
        FILE *fp = fopen(pub_file, "w");
        if (!fp) goto done;
        if (PEM_write_PUBKEY(fp, pk) != 1) {
            fclose(fp);
            goto done;
        }
        fclose(fp);
        chmod(pub_file, 0644);
    }
    ret = 0;

done:
    if (ret) log_ssl_errors("gen_rsa_keys_to_file");
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ── RSA encrypt/decrypt from PEM buffer ───────────────────── */

static int rsa_oaep_op(const unsigned char *pem, size_t pem_len,
                       int is_encrypt,
                       const unsigned char *in, size_t inlen,
                       unsigned char *out, size_t *outlen)
{
    int ret = -1;
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) return -1;

    EVP_PKEY *pk = NULL;
    if (is_encrypt)
        pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    else
        pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pk) { log_ssl_errors("PEM_read"); return -1; }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!ctx) { EVP_PKEY_free(pk); return -1; }

    if (is_encrypt) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0) goto cc;
    } else {
        if (EVP_PKEY_decrypt_init(ctx) <= 0) goto cc;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx,
                                     RSA_PKCS1_OAEP_PADDING) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        goto cc;

    size_t ol = 0;
    if (is_encrypt) {
        if (EVP_PKEY_encrypt(ctx, NULL, &ol, in, inlen) <= 0)
            goto cc;
        if (ol > *outlen) goto cc;
        if (EVP_PKEY_encrypt(ctx, out, &ol, in, inlen) <= 0)
            goto cc;
    } else {
        if (EVP_PKEY_decrypt(ctx, NULL, &ol, in, inlen) <= 0)
            goto cc;
        if (ol > *outlen) goto cc;
        if (EVP_PKEY_decrypt(ctx, out, &ol, in, inlen) <= 0)
            goto cc;
    }
    *outlen = ol;
    ret = 0;

cc:
    if (ret) log_ssl_errors(is_encrypt ? "rsa_encrypt" : "rsa_decrypt");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return ret;
}

int rsa_encrypt_pem(const unsigned char *pub_pem, size_t pub_len,
                    const unsigned char *pt, size_t ptlen,
                    unsigned char *out, size_t *outlen)
{
    return rsa_oaep_op(pub_pem, pub_len, 1, pt, ptlen, out, outlen);
}

int rsa_decrypt_pem(const unsigned char *priv_pem, size_t priv_len,
                    const unsigned char *ct, size_t ctlen,
                    unsigned char *out, size_t *outlen)
{
    return rsa_oaep_op(priv_pem, priv_len, 0, ct, ctlen, out, outlen);
}

/* RSA from file (for vault/local operations) */
int rsa_encrypt_file(const char *pub_file,
                     const unsigned char *pt, size_t ptlen,
                     unsigned char **out, size_t *outlen)
{
    int ret = -1;
    FILE *fp = fopen(pub_file, "r");
    if (!fp) return -1;

    EVP_PKEY *pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pk) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!ctx) { EVP_PKEY_free(pk); return -1; }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto cc;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx,
                                     RSA_PKCS1_OAEP_PADDING) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        goto cc;

    size_t ol = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &ol, pt, ptlen) <= 0) goto cc;
    *out = OPENSSL_malloc(ol);
    if (EVP_PKEY_encrypt(ctx, *out, &ol, pt, ptlen) <= 0) {
        OPENSSL_free(*out); *out = NULL; goto cc;
    }
    *outlen = ol;
    ret = 0;

cc:
    if (ret) log_ssl_errors("rsa_encrypt_file");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return ret;
}

int rsa_decrypt_file(const char *priv_file,
                     const unsigned char *ct, size_t ctlen,
                     unsigned char **out, size_t *outlen)
{
    int ret = -1;
    FILE *fp = fopen(priv_file, "r");
    if (!fp) return -1;

    EVP_PKEY *pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pk) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!ctx) { EVP_PKEY_free(pk); return -1; }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto cc;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx,
                                     RSA_PKCS1_OAEP_PADDING) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        goto cc;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        goto cc;

    size_t ol = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &ol, ct, ctlen) <= 0) goto cc;
    *out = OPENSSL_malloc(ol);
    if (EVP_PKEY_decrypt(ctx, *out, &ol, ct, ctlen) <= 0) {
        OPENSSL_free(*out); *out = NULL; goto cc;
    }
    *outlen = ol;
    ret = 0;

cc:
    if (ret) log_ssl_errors("rsa_decrypt_file");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return ret;
}

/* ── PBKDF2-HMAC-SHA256 password key derivation ───────────── */

int password_derive_key(const char *password,
                        const unsigned char *salt, size_t salt_len,
                        unsigned char *key_out, size_t key_len)
{
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, (int)salt_len,
                           PBKDF2_ITERATIONS,
                           EVP_sha256(),
                           (int)key_len, key_out) != 1) {
        log_ssl_errors("PBKDF2");
        return -1;
    }
    return 0;
}

int password_make_verifier(const unsigned char *derived_key,
                           unsigned char *verifier_out)
{
    unsigned int md_len = 0;
    const char *label = "securedrop-password-verify-v4";
    unsigned char *result = HMAC(EVP_sha256(),
                                 derived_key, HASH_LEN,
                                 (unsigned char *)label,
                                 strlen(label),
                                 verifier_out, &md_len);
    return result ? 0 : -1;
}

int password_check_verifier(const unsigned char *derived_key,
                            const unsigned char *verifier)
{
    unsigned char computed[HASH_LEN];
    if (password_make_verifier(derived_key, computed) != 0)
        return -1;

    /* Constant-time comparison */
    if (CRYPTO_memcmp(computed, verifier, HASH_LEN) != 0) {
        secure_wipe(computed, HASH_LEN);
        return -1;
    }
    secure_wipe(computed, HASH_LEN);
    return 0;
}

/* ── SHA-256 ───────────────────────────────────────────────── */

int compute_sha256(const unsigned char *data, size_t len,
                   unsigned char *hash_out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto end;
    if (EVP_DigestUpdate(ctx, data, len) != 1) goto end;
    if (EVP_DigestFinal_ex(ctx, hash_out, &md_len) != 1) goto end;
    ret = 0;

end:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int compute_sha256_hex(const unsigned char *data, size_t len,
                       char *hex_out)
{
    unsigned char hash[HASH_LEN];
    if (compute_sha256(data, len, hash) != 0) return -1;
    bytes_to_hex(hash, HASH_LEN, hex_out);
    return 0;
}

/* ── Vault encrypt/decrypt (local storage) ─────────────────── */

int vault_encrypt_file(const char *src, const char *dst)
{
    unsigned char key[AES_KEY_LEN], iv[AES_IV_LEN];
    if (secure_random(key, AES_KEY_LEN) != 0) return -1;
    if (secure_random(iv, AES_IV_LEN) != 0) return -1;

    FILE *fin = fopen(src, "rb");
    if (!fin) {
        secure_wipe(key, AES_KEY_LEN);
        return -1;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (file_size < 0 || file_size > 256L * 1024 * 1024) {
        fclose(fin);
        secure_wipe(key, AES_KEY_LEN);
        return -1;
    }

    unsigned char *ekey = NULL;
    size_t eklen = 0;
    if (rsa_encrypt_file(RSA_PUB_FILE, key, AES_KEY_LEN, &ekey, &eklen) != 0) {
        secure_wipe(key, AES_KEY_LEN);
        fclose(fin);
        return -1;
    }

    FILE *fout = fopen(dst, "wb");
    if (!fout) {
        secure_wipe(key, AES_KEY_LEN);
        OPENSSL_free(ekey);
        fclose(fin);
        return -1;
    }

    int ret = -1;

    if (fwrite(iv, 1, AES_IV_LEN, fout) != AES_IV_LEN)
        goto fail;

    uint32_t ekl32 = htonl((uint32_t)eklen);
    if (fwrite(&ekl32, 4, 1, fout) != 1)
        goto fail;
    if (fwrite(ekey, 1, eklen, fout) != eklen)
        goto fail;

    OPENSSL_free(ekey);
    ekey = NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto fail;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto fail_ctx;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) != 1)
        goto fail_ctx;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto fail_ctx;

    secure_wipe(key, AES_KEY_LEN);

    unsigned char inbuf[8192], outbuf[8192 + 128];
    int outl;
    size_t nr;
    while ((nr = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outl, inbuf, (int)nr) != 1)
            goto fail_ctx;
        if (fwrite(outbuf, 1, (size_t)outl, fout) != (size_t)outl)
            goto fail_ctx;
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outl) != 1)
        goto fail_ctx;
    if (fwrite(outbuf, 1, (size_t)outl, fout) != (size_t)outl)
        goto fail_ctx;

    unsigned char tag[AES_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) != 1)
        goto fail_ctx;
    if (fwrite(tag, 1, AES_TAG_LEN, fout) != AES_TAG_LEN)
        goto fail_ctx;

    ret = 0;

fail_ctx:
    EVP_CIPHER_CTX_free(ctx);
fail:
    if (ekey)
        OPENSSL_free(ekey);
    secure_wipe(key, AES_KEY_LEN);
    fclose(fin);
    fclose(fout);
    if (ret != 0)
        unlink(dst);
    return ret;
}

int vault_decrypt_file(const char *src, const char *dst)
{
    FILE *fin = fopen(src, "rb");
    if (!fin) return -1;

    unsigned char iv[AES_IV_LEN];
    if (fread(iv, 1, AES_IV_LEN, fin) != AES_IV_LEN) {
        fclose(fin);
        return -1;
    }

    uint32_t ekl32;
    if (fread(&ekl32, 4, 1, fin) != 1) {
        fclose(fin);
        return -1;
    }
    uint32_t eklen = ntohl(ekl32);

    if (eklen > 8192) {
        fclose(fin);
        return -1;
    }

    unsigned char *ekey = malloc(eklen);
    if (!ekey) {
        fclose(fin);
        return -1;
    }
    if (fread(ekey, 1, eklen, fin) != eklen) {
        free(ekey);
        fclose(fin);
        return -1;
    }

    unsigned char *key = NULL;
    size_t klen = 0;
    if (rsa_decrypt_file(RSA_PRIV_FILE, ekey, eklen, &key, &klen) != 0) {
        free(ekey);
        fclose(fin);
        return -1;
    }
    free(ekey);

    long cur = ftell(fin);
    if (cur < 0) {
        secure_wipe(key, klen);
        OPENSSL_free(key);
        fclose(fin);
        return -1;
    }
    fseek(fin, 0, SEEK_END);
    long end = ftell(fin);
    fseek(fin, cur, SEEK_SET);
    long ct_len = end - cur - AES_TAG_LEN;

    if (ct_len < 0 || ct_len > 256L * 1024 * 1024) {
        secure_wipe(key, klen);
        OPENSSL_free(key);
        fclose(fin);
        return -1;
    }

    unsigned char *ct_data = malloc((size_t)ct_len);
    if (!ct_data) {
        secure_wipe(key, klen);
        OPENSSL_free(key);
        fclose(fin);
        return -1;
    }

    if ((long)fread(ct_data, 1, (size_t)ct_len, fin) != ct_len) {
        free(ct_data);
        secure_wipe(key, klen);
        OPENSSL_free(key);
        fclose(fin);
        return -1;
    }

    unsigned char tag[AES_TAG_LEN];
    if (fread(tag, 1, AES_TAG_LEN, fin) != AES_TAG_LEN) {
        free(ct_data);
        secure_wipe(key, klen);
        OPENSSL_free(key);
        fclose(fin);
        return -1;
    }
    fclose(fin);

    unsigned char *pt_data = malloc((size_t)ct_len + 128);
    if (!pt_data) {
        free(ct_data);
        secure_wipe(key, klen);
        OPENSSL_free(key);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(pt_data);
        free(ct_data);
        secure_wipe(key, klen);
        OPENSSL_free(key);
        return -1;
    }

    int ret = -1;
    int outl = 0, tmpl = 0;
    size_t pt_total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) != 1)
        goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    secure_wipe(key, klen);
    OPENSSL_free(key);
    key = NULL;

    if (EVP_DecryptUpdate(ctx, pt_data, &outl, ct_data, (int)ct_len) != 1)
        goto cleanup;
    pt_total = (size_t)outl;

    free(ct_data);
    ct_data = NULL;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, pt_data + pt_total, &tmpl) != 1)
        goto cleanup;
    pt_total += (size_t)tmpl;

    {
        FILE *fout = fopen(dst, "wb");
        if (!fout)
            goto cleanup;
        if (fwrite(pt_data, 1, pt_total, fout) != pt_total) {
            fclose(fout);
            unlink(dst);
            goto cleanup;
        }
        fclose(fout);
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (pt_data) {
        secure_wipe(pt_data, (size_t)ct_len + 128);
        free(pt_data);
    }
    if (ct_data)
        free(ct_data);
    if (key) {
        secure_wipe(key, klen);
        OPENSSL_free(key);
    }
    if (ret != 0)
        unlink(dst);
    return ret;
}