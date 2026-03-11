#ifndef STORAGE_H
#define STORAGE_H

#include "app.h"
#include "util.h"

void storage_init(void);

int storage_store_chunk(const char *file_id,
                        uint32_t chunk_idx,
                        const unsigned char *data, size_t len,
                        int log_target);

int storage_retrieve_chunk(const char *file_id,
                           uint32_t chunk_idx,
                           int sub_server_idx,
                           Buf *out,
                           int log_target);

int storage_save_meta(const StoredFileMeta *meta,
                      int log_target);
int storage_load_meta(const char *file_id,
                      StoredFileMeta *meta_out);
int storage_load_all_meta(int log_target);

int storage_delete_file(const char *file_id,
                        int log_target);

/* Sub-server management */
int  storage_add_subserver(const char *address, int port,
                           int log_target);
int  storage_add_subservers_batch(int count, int log_target);
int  storage_start_subserver(int index, int log_target);
void storage_start_all_subservers(int log_target);
void storage_stop_subservers(void);
int  storage_active_subserver_count(void);
int  storage_validate_port(int port);

enum MHD_Result subserver_handler(
    void *cls, struct MHD_Connection *conn,
    const char *url, const char *method,
    const char *version, const char *upload_data,
    size_t *upload_data_size, void **con_cls);

#endif /* STORAGE_H */