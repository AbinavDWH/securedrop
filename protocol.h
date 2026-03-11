#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "app.h"
#include "util.h"
#include "crypto.h"

/*
 * Wire format for UPLOAD (sender → server):
 *
 * [4]  magic           "SD4U"
 * [4]  version         1
 * [32] password_salt
 * [32] password_verify (HMAC of derived key)
 * [4]  rsa_pub_pem_len
 * [N]  rsa_pub_pem     (plaintext — needed to re-encrypt for download)
 * [12] rsa_priv_iv
 * [16] rsa_priv_tag
 * [4]  enc_rsa_priv_len
 * [N]  enc_rsa_priv    (AES-encrypted with password-derived key)
 * [4]  enc_master_key_len
 * [N]  enc_master_key  (RSA-encrypted master key)
 * [4]  filename_len
 * [N]  filename
 * [8]  file_size
 * [4]  chunk_count
 * For each chunk:
 *   [4]  global_index
 *   [4]  ciphertext_len
 *   [12] iv
 *   [16] tag
 *   [N]  ciphertext
 *
 * Wire format for DOWNLOAD RESPONSE (server → receiver):
 *   Same format as upload, but server re-wraps master key
 *   with a fresh RSA keypair tied to the download session.
 *   Receiver provides password to unlock.
 */

#define PROTO_MAGIC_UPLOAD   "SD4U"
#define PROTO_MAGIC_DOWNLOAD "SD4D"
#define PROTO_VERSION        1

/* Build upload payload from local file(s) */
int protocol_build_upload(const char *filepath,
                          const char *password,
                          Buf *payload,
                          char *file_id_out,
                          int log_target);

/* Parse upload payload and store on server */
int protocol_parse_upload(const unsigned char *data, size_t len,
                          char *file_id_out,
                          int log_target);

/* Build download response (server side) */
int protocol_build_download(const char *file_id,
                            const char *password,
                            Buf *response,
                            int log_target);

/* Parse download response and reconstruct file (receiver side) */
int protocol_parse_download(const unsigned char *data, size_t len,
                            const char *password,
                            int log_target);

/* Parallel transfer metadata functions */
int protocol_parse_upload_metadata(
    const uint8_t *data, size_t len,
    char *file_id_out, int log_target);

int protocol_build_download_metadata(
    const char *file_id, const char *password,
    Buf *out, int log_target);

#endif /* PROTOCOL_H */