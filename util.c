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

#include "util.h"
#include <openssl/crypto.h>
#include <ctype.h>

void human_size(size_t bytes, char *buf, size_t bufsz)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)bytes;
    int i = 0;

    while (v >= 1024.0 && i < 4) {
        v /= 1024.0;
        i++;
    }
    if (i == 0)
        snprintf(buf, bufsz, "%zu B", bytes);
    else
        snprintf(buf, bufsz, "%.2f %s", v, units[i]);
}

void get_timestamp(char *buf, size_t bufsz)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, bufsz, "%H:%M:%S", tm);
}

/* ── Dynamic buffer ────────────────────────────────────────── */

void buf_init(Buf *b)
{
    memset(b, 0, sizeof(*b));
}

int buf_add(Buf *b, const void *src, size_t n)
{
    if (n == 0) return 0;
    if (b->len + n < b->len)
        return -1;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n) {
            size_t doubled = nc * 2;
            if (doubled <= nc)
                return -1;
            nc = doubled;
        }
        unsigned char *t = realloc(b->data, nc);
        if (!t) return -1;
        b->data = t;
        b->cap = nc;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

void buf_u32(Buf *b, uint32_t v)
{
    uint32_t n = htonl(v);
    buf_add(b, &n, 4);
}

void buf_u64(Buf *b, uint64_t v)
{
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xFFFFFFFF));
    buf_add(b, &hi, 4);
    buf_add(b, &lo, 4);
}

void buf_free(Buf *b)
{
    if (b->data) {
        OPENSSL_cleanse(b->data, b->cap);
        free(b->data);
    }
    memset(b, 0, sizeof(*b));
}

/* ──────────────────────────────────────────────────────────────
 * buf_reserve — pre-allocate capacity without changing length
 *
 * Ensures the buffer can hold at least `n` MORE bytes
 * without realloc. Call before bulk buf_add() to avoid
 * repeated doubling during large downloads.
 *
 * Without this, assembling 500MB from 500 chunks causes:
 *   4KB → 8KB → 16KB → ... → 512MB = ~17 reallocs
 *   Each realloc copies ALL previous data
 *
 * With this, ONE allocation upfront:
 *   reserve(500MB) → single malloc
 *   All buf_add() calls just memcpy, no realloc
 * ────────────────────────────────────────────────────────────── */

void buf_reserve(Buf *b, size_t n)
{
    if (!b) return;
    if (b->len + n < b->len)
        return;
    size_t needed = b->len + n;

    if (!b->data) {
        b->data = malloc(needed);
        if (b->data)
            b->cap = needed;
        else
            b->cap = 0;
        b->len = 0;
        return;
    }

    if (b->cap >= needed)
        return;

    unsigned char *tmp = realloc(b->data, needed);
    if (tmp) {
        b->data = tmp;
        b->cap = needed;
    }
}

/* ── Network byte-order readers ────────────────────────────── */

uint32_t rd32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

uint64_t rd64(const unsigned char *p)
{
    uint64_t hi = (uint64_t)rd32(p);
    uint64_t lo = (uint64_t)rd32(p + 4);
    return (hi << 32) | lo;
}

/* ── Hex conversion ────────────────────────────────────────── */

void bytes_to_hex(const unsigned char *in, size_t len, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hx[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hx[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0 || hlen / 2 > outlen) return -1;

    for (size_t i = 0; i < hlen / 2; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (!isxdigit(hi) || !isxdigit(lo)) return -1;

        unsigned char bhi = (unsigned char)(isdigit(hi) ? hi - '0' : tolower(hi) - 'a' + 10);
        unsigned char blo = (unsigned char)(isdigit(lo) ? lo - '0' : tolower(lo) - 'a' + 10);
        out[i] = (bhi << 4) | blo;
    }
    return (int)(hlen / 2);
}

/* ── Filesystem helpers ────────────────────────────────────── */

int mkdir_p(const char *path, mode_t mode)
{
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);

    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    return mkdir(tmp, mode);
}

int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}