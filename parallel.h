#ifndef PARALLEL_H
#define PARALLEL_H

#include "util.h"

#define PARALLEL_MAX_SERVERS   16
#define PARALLEL_MAX_THREADS   16    /* was 8 */
#define PARALLEL_PIPELINE_DEPTH 4    /* NEW: chunks per connection */

typedef struct {
    char host[512];
    int  port;
    int  active;
} SubServerEntry;

typedef struct {
    SubServerEntry entries[PARALLEL_MAX_SERVERS];
    int            count;
} SubServerList;

int parallel_get_server_list(
    const char *server_addr,
    const char *proxy,
    SubServerList *out,
    int log_target);

int parallel_warmup_circuits(
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    int log_target);

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
    int log_target);

int parallel_download_chunks(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    int chunk_count,
    const uint32_t *chunk_sizes,
    Buf *assembled,
    int log_target);

/* NEW: Streaming download — writes chunks
   to disk as they arrive instead of buffering
   entire file in RAM */
int parallel_download_chunks_streaming(
    const char *server_addr,
    const char **proxies,
    int num_proxies,
    const SubServerList *servers,
    const char *file_id,
    int chunk_count,
    const uint32_t *chunk_sizes,
    Buf **chunk_bufs_out,
    int log_target);

void parallel_free_server_list(SubServerList *s);

#endif