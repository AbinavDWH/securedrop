#ifndef UTIL_H
#define UTIL_H

#include "app.h"

void     human_size(size_t bytes, char *buf, size_t bufsz);
void     get_timestamp(char *buf, size_t bufsz);

/* Dynamic buffer */
void     buf_init(Buf *b);
int      buf_add(Buf *b, const void *src, size_t n);
void     buf_u32(Buf *b, uint32_t v);
void     buf_u64(Buf *b, uint64_t v);
void     buf_free(Buf *b);
void     buf_reserve(Buf *b, size_t n);

/* Network byte-order readers */
uint32_t rd32(const unsigned char *p);
uint64_t rd64(const unsigned char *p);

/* Hex conversion */
void     bytes_to_hex(const unsigned char *in, size_t len, char *out);
int      hex_to_bytes(const char *hex, unsigned char *out, size_t outlen);

/* Filesystem */
int      mkdir_p(const char *path, mode_t mode);
int      file_exists(const char *path);
long     file_size(const char *path);

#endif /* UTIL_H */