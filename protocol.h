#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "app.h"
#include "util.h"
#include "crypto.h"

#define PROTO_MAGIC_UPLOAD   "SD4U"
#define PROTO_MAGIC_DOWNLOAD "SD4D"
#define PROTO_VERSION        1

int protocol_build_upload(const char *filepath,
                          const char *password,
                          Buf *payload,
                          char *file_id_out,
                          int log_target);

int protocol_parse_upload(const unsigned char *data,
                          size_t len,
                          char *file_id_out,
                          int log_target);

int protocol_build_download(const char *file_id,
                            const char *password,
                            Buf *response,
                            int log_target);

int protocol_parse_download(const unsigned char *data,
                            size_t len,
                            const char *password,
                            int log_target);

/* CHANGED: added external_file_id parameter
   Pass NULL to compute from data (backward compat)
   Pass client's file_id for parallel mode */
int protocol_parse_upload_metadata(
    const uint8_t *data, size_t len,
    char *file_id_out,
    const char *external_file_id,
    int log_target);

int protocol_build_download_metadata(
    const char *file_id, const char *password,
    Buf *out, int log_target);

#endif /* PROTOCOL_H */