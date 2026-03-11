#ifndef TOR_POOL_H
#define TOR_POOL_H

#include "app.h"

#define TOR_POOL_MAX        16
#define TOR_POOL_BASE_PORT  9060
#define TOR_POOL_TIMEOUT    90

typedef struct {
    pid_t pid;
    int   socks_port;
    char  proxy[128];
    char  data_dir[512];
    int   ready;
} TorPoolEntry;

typedef struct {
    TorPoolEntry    entries[TOR_POOL_MAX];
    int             count;
    int             next;
    pthread_mutex_t mutex;
    int             initialized;
} TorPool;

/* Start N independent Tor SOCKS5 proxies */
int tor_pool_start(int count, int log_target);

/* Get proxy URL by index */
const char *tor_pool_get_proxy(int index);

/* Round-robin next proxy */
const char *tor_pool_next_proxy(void);

/* How many are ready */
int tor_pool_ready_count(void);

/* Build array of proxy strings for parallel use */
int tor_pool_get_all_proxies(const char **out,
                             int max_out);

/* Stop all Tor instances */
void tor_pool_stop(int log_target);

#endif /* TOR_POOL_H */