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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "app.h"

/* Secure memory */
int  secure_random(unsigned char *buf, size_t len);
void secure_wipe(void *buf, size_t len);

/* Per-chunk key derivation: HKDF-SHA256 */
int derive_chunk_key(const unsigned char *master, size_t mlen,
                     uint32_t chunk_idx,
                     unsigned char *out, size_t olen);

/* AES-256-GCM chunk encryption/decryption */
int encrypt_chunk(const unsigned char *key, uint32_t chunk_idx,
                  const unsigned char *pt, size_t ptlen,
                  unsigned char *iv_out,
                  unsigned char *ct_out, size_t *ctlen_out,
                  unsigned char *tag_out);

int decrypt_chunk(const unsigned char *key, uint32_t chunk_idx,
                  const unsigned char *iv,
                  const unsigned char *tag,
                  const unsigned char *ct, size_t ctlen,
                  unsigned char *pt_out, size_t *ptlen_out);

/* AES-256-GCM blob encryption (for RSA private key wrapping) */
int encrypt_blob(const unsigned char *key,
                 const unsigned char *pt, size_t ptlen,
                 unsigned char *iv_out,
                 unsigned char *ct_out, size_t *ctlen_out,
                 unsigned char *tag_out);

int decrypt_blob(const unsigned char *key,
                 const unsigned char *iv,
                 const unsigned char *tag,
                 const unsigned char *ct, size_t ctlen,
                 unsigned char *pt_out, size_t *ptlen_out);

/* RSA-4096 OAEP-SHA256 */
int gen_rsa_keys_to_pem(unsigned char *pub_pem, size_t *pub_len,
                        unsigned char *priv_pem, size_t *priv_len);
int gen_rsa_keys_to_file(const char *pub_file, const char *priv_file);
int rsa_encrypt_pem(const unsigned char *pub_pem, size_t pub_len,
                    const unsigned char *pt, size_t ptlen,
                    unsigned char *out, size_t *outlen);
int rsa_decrypt_pem(const unsigned char *priv_pem, size_t priv_len,
                    const unsigned char *ct, size_t ctlen,
                    unsigned char *out, size_t *outlen);
int rsa_encrypt_file(const char *pub_file,
                     const unsigned char *pt, size_t ptlen,
                     unsigned char **out, size_t *outlen);
int rsa_decrypt_file(const char *priv_file,
                     const unsigned char *ct, size_t ctlen,
                     unsigned char **out, size_t *outlen);

/* Password-based key derivation: PBKDF2-HMAC-SHA256 */
int password_derive_key(const char *password,
                        const unsigned char *salt, size_t salt_len,
                        unsigned char *key_out, size_t key_len);
int password_make_verifier(const unsigned char *derived_key,
                           unsigned char *verifier_out);
int password_check_verifier(const unsigned char *derived_key,
                            const unsigned char *verifier);

/* SHA-256 hashing */
int compute_sha256(const unsigned char *data, size_t len,
                   unsigned char *hash_out);
int compute_sha256_hex(const unsigned char *data, size_t len,
                       char *hex_out);

/* Vault (local file encryption with RSA-wrapped AES key) */
int vault_encrypt_file(const char *src_path, const char *dst_path);
int vault_decrypt_file(const char *src_path, const char *dst_path);

/* Error logging */
void log_ssl_errors(const char *context);

#endif /* CRYPTO_H */