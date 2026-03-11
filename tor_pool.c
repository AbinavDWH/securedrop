#include "tor_pool.h"
#include "gui_helpers.h"
#include "util.h"

#include <signal.h>
#include <sys/wait.h>

static TorPool pool = {0};

/* ────────────────────────────────────────────────────────────
   FIND TOR BINARY
   ──────────────────────────────────────────────────────────── */

static int find_tor_bin(char *out, size_t sz)
{
    const char *paths[] = {
        "/usr/bin/tor",
        "/usr/sbin/tor",
        "/usr/local/bin/tor",
        "/snap/bin/tor",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0) {
            strncpy(out, paths[i], sz - 1);
            out[sz - 1] = '\0';
            return 0;
        }
    }

    FILE *fp = popen("which tor 2>/dev/null", "r");
    if (fp) {
        if (fgets(out, (int)sz, fp)) {
            size_t len = strlen(out);
            if (len > 0 && out[len - 1] == '\n')
                out[len - 1] = '\0';
            pclose(fp);
            if (access(out, X_OK) == 0)
                return 0;
        } else {
            pclose(fp);
        }
    }

    return -1;
}

/* ────────────────────────────────────────────────────────────
   CHECK IF PORT IS ACCEPTING CONNECTIONS
   ──────────────────────────────────────────────────────────── */

static int port_open(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               &tv, sizeof(tv));

    int ok = (connect(s, (struct sockaddr *)&addr,
                      sizeof(addr)) == 0);
    close(s);
    return ok;
}

/* ────────────────────────────────────────────────────────────
   VERIFY SOCKS5 HANDSHAKE
   Some ports accept TCP but aren't SOCKS5.
   ──────────────────────────────────────────────────────────── */

static int verify_socks5_port(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct timeval tv = {3, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               &tv, sizeof(tv));

    if (connect(s, (struct sockaddr *)&addr,
                sizeof(addr)) != 0) {
        close(s);
        return 0;
    }

    /* SOCKS5 greeting: version=5, 1 method, no auth */
    unsigned char greeting[] = {0x05, 0x01, 0x00};
    if (send(s, greeting, 3, 0) != 3) {
        close(s);
        return 0;
    }

    unsigned char response[2] = {0};
    ssize_t n = recv(s, response, 2, 0);
    close(s);

    /* Valid SOCKS5 response: version=5, method */
    return (n == 2 && response[0] == 0x05);
}

/* ────────────────────────────────────────────────────────────
   START TOR POOL
   Launches N independent Tor SOCKS5 proxy instances.
   Each on its own port with own DataDirectory.
   ──────────────────────────────────────────────────────────── */

int tor_pool_start(int count, int log_target)
{
    /* Already running? Return existing count */
    if (pool.initialized && pool.count > 0) {
        int ready = tor_pool_ready_count();
        if (ready > 0) {
            gui_post_log(log_target,
                "Tor pool already running: "
                "%d/%d ready",
                ready, pool.count);
            return ready;
        }
    }

    if (count <= 0) count = 8;
    if (count > TOR_POOL_MAX)
        count = TOR_POOL_MAX;

    char tor_bin[512];
    if (find_tor_bin(tor_bin, sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor binary not found — "
            "cannot create proxy pool");
        gui_post_log(log_target,
            "  sudo apt install tor");
        return 0;
    }

    memset(&pool, 0, sizeof(pool));
    pthread_mutex_init(&pool.mutex, NULL);

    gui_post_log(log_target,
        "═══════════════════════════════════");
    gui_post_log(log_target,
        "Starting Tor proxy pool: "
        "%d instances", count);
    gui_post_log(log_target,
        "Ports: %d–%d",
        TOR_POOL_BASE_PORT,
        TOR_POOL_BASE_PORT + count - 1);
    gui_post_log(log_target,
        "═══════════════════════════════════");

    int launched = 0;

    for (int i = 0; i < count; i++) {
        int sport = TOR_POOL_BASE_PORT + i;
        TorPoolEntry *e = &pool.entries[pool.count];

        /* Check if port already in use
           (leftover from previous run) */
        if (port_open(sport)) {
            if (verify_socks5_port(sport)) {
                gui_post_log(log_target,
                    "  Pool[%d] port %d already "
                    "active (reusing)",
                    i, sport);

                e->pid = 0;  /* not our process */
                e->socks_port = sport;
                snprintf(e->proxy, sizeof(e->proxy),
                    "socks5h://127.0.0.1:%d", sport);
                e->ready = 1;
                pool.count++;
                launched++;
                continue;
            }
            /* Port open but not SOCKS5 — skip */
            gui_post_log(log_target,
                "  Pool[%d] port %d in use "
                "(not SOCKS5), skipping", i, sport);
            continue;
        }

        /* Create DataDirectory */
        char ddir[512];
        snprintf(ddir, sizeof(ddir),
                 "tor_data/pool_%d", i);
        mkdir_p(ddir, 0700);

        /* Write minimal torrc */
        char torrc_path[600];
        snprintf(torrc_path, sizeof(torrc_path),
                 "%s/torrc", ddir);

        FILE *fp = fopen(torrc_path, "w");
        if (!fp) {
            gui_post_log(log_target,
                "  Pool[%d] cannot create torrc",
                i);
            continue;
        }

        fprintf(fp,
            "# Tor pool instance %d\n"
            "SocksPort %d\n"
            "DataDirectory %s\n"
            "Log notice file %s/tor.log\n"
            "AvoidDiskWrites 1\n"
            "SafeSocks 0\n",
            i, sport, ddir, ddir);

        fclose(fp);

        /* Fork and exec Tor */
        pid_t pid = fork();

        if (pid < 0) {
            gui_post_log(log_target,
                "  Pool[%d] fork failed", i);
            continue;
        }

        if (pid == 0) {
            /* Child process */

            /* Redirect stdout/stderr */
            char logpath[600];
            snprintf(logpath, sizeof(logpath),
                     "%s/stdout.log", ddir);
            int fd = open(logpath,
                O_WRONLY | O_CREAT | O_TRUNC,
                0600);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            /* Close inherited FDs */
            for (int f = 3; f < 1024; f++)
                close(f);

            execl(tor_bin, "tor",
                  "-f", torrc_path, NULL);

            _exit(127);
        }

        /* Parent */
        e->pid = pid;
        e->socks_port = sport;
        snprintf(e->proxy, sizeof(e->proxy),
            "socks5h://127.0.0.1:%d", sport);
        strncpy(e->data_dir, ddir,
                sizeof(e->data_dir) - 1);
        e->ready = 0;
        pool.count++;
        launched++;

        gui_post_log(log_target,
            "  Pool[%d] launched (PID %d, "
            "port %d)",
            i, pid, sport);
    }

    if (launched == 0) {
        gui_post_log(log_target,
            "No Tor pool instances launched");
        return 0;
    }

    /* ── Wait for bootstrap ────────────────────────── */

    gui_post_log(log_target,
        "Waiting for %d Tor instances to "
        "bootstrap (timeout %ds)...",
        launched, TOR_POOL_TIMEOUT);

    time_t start = time(NULL);
    int last_ready = 0;

    while (time(NULL) - start < TOR_POOL_TIMEOUT) {
        int ready = 0;

        for (int i = 0; i < pool.count; i++) {
            TorPoolEntry *e = &pool.entries[i];

            if (e->ready) {
                ready++;
                continue;
            }

            /* Check if process died */
            if (e->pid > 0) {
                int status;
                pid_t r = waitpid(e->pid, &status,
                                  WNOHANG);
                if (r > 0) {
                    gui_post_log(log_target,
                        "  Pool[%d] Tor exited "
                        "(status %d)",
                        i, status);
                    e->pid = 0;
                    continue;
                }
            }

            /* Check if SOCKS5 port is ready */
            if (verify_socks5_port(e->socks_port)) {
                e->ready = 1;
                ready++;
                gui_post_log(log_target,
                    "  \xE2\x9C\x93 Pool[%d] "
                    "READY (port %d)",
                    i, e->socks_port);
            }
        }

        /* Progress update */
        if (ready > last_ready) {
            gui_post_log(log_target,
                "  Bootstrap: %d/%d ready",
                ready, pool.count);
            last_ready = ready;
        }

        /* All ready */
        if (ready >= pool.count)
            break;

        /* Have at least half and waited 60s */
        int elapsed = (int)(time(NULL) - start);
        if (ready > 0 &&
            ready >= pool.count / 2 &&
            elapsed > 60) {
            gui_post_log(log_target,
                "  Using %d/%d (timeout "
                "approaching)",
                ready, pool.count);
            break;
        }

        /* At least 1 and waited 45s */
        if (ready > 0 && elapsed > 45) {
            gui_post_log(log_target,
                "  Using %d/%d available",
                ready, pool.count);
            break;
        }

        usleep(500000);  /* 0.5s */
    }

    pool.initialized = 1;

    int final_ready = tor_pool_ready_count();

    gui_post_log(log_target,
        "═══════════════════════════════════");
    gui_post_log(log_target,
        "Tor pool: %d/%d circuits ready",
        final_ready, pool.count);

    if (final_ready > 0) {
        gui_post_log(log_target,
            "Each circuit = independent "
            "Tor path");
        gui_post_log(log_target,
            "Parallel bandwidth: ~%d× single",
            final_ready);
    }
    gui_post_log(log_target,
        "═══════════════════════════════════");

    return final_ready;
}

/* ────────────────────────────────────────────────────────────
   GET PROXY BY INDEX
   ──────────────────────────────────────────────────────────── */

const char *tor_pool_get_proxy(int index)
{
    if (!pool.initialized) return NULL;

    /* Find the index'th ready proxy */
    int found = 0;
    for (int i = 0; i < pool.count; i++) {
        if (pool.entries[i].ready) {
            if (found == index)
                return pool.entries[i].proxy;
            found++;
        }
    }

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   ROUND-ROBIN NEXT PROXY
   ──────────────────────────────────────────────────────────── */

const char *tor_pool_next_proxy(void)
{
    if (!pool.initialized) return NULL;

    int ready = tor_pool_ready_count();
    if (ready == 0) return NULL;

    pthread_mutex_lock(&pool.mutex);
    int idx = pool.next % ready;
    pool.next++;
    pthread_mutex_unlock(&pool.mutex);

    return tor_pool_get_proxy(idx);
}

/* ────────────────────────────────────────────────────────────
   READY COUNT
   ──────────────────────────────────────────────────────────── */

int tor_pool_ready_count(void)
{
    int count = 0;
    for (int i = 0; i < pool.count; i++) {
        if (pool.entries[i].ready)
            count++;
    }
    return count;
}

/* ────────────────────────────────────────────────────────────
   BUILD ARRAY OF ALL READY PROXY STRINGS
   Returns number of proxies written to out[]
   ──────────────────────────────────────────────────────────── */

int tor_pool_get_all_proxies(const char **out,
                             int max_out)
{
    int n = 0;
    for (int i = 0; i < pool.count && n < max_out;
         i++) {
        if (pool.entries[i].ready) {
            out[n++] = pool.entries[i].proxy;
        }
    }
    return n;
}

/* ────────────────────────────────────────────────────────────
   STOP ALL TOR POOL INSTANCES
   ──────────────────────────────────────────────────────────── */

void tor_pool_stop(int log_target)
{
    if (!pool.initialized) return;

    gui_post_log(log_target,
        "Stopping Tor pool (%d instances)...",
        pool.count);

    /* SIGTERM all */
    for (int i = 0; i < pool.count; i++) {
        if (pool.entries[i].pid > 0) {
            kill(pool.entries[i].pid, SIGTERM);
        }
    }

    /* Wait 5 seconds */
    for (int w = 0; w < 10; w++) {
        int alive = 0;
        for (int i = 0; i < pool.count; i++) {
            if (pool.entries[i].pid > 0) {
                int status;
                pid_t r = waitpid(
                    pool.entries[i].pid,
                    &status, WNOHANG);
                if (r > 0) {
                    pool.entries[i].pid = 0;
                } else {
                    alive++;
                }
            }
        }
        if (alive == 0) break;
        usleep(500000);
    }

    /* Force kill any remaining */
    for (int i = 0; i < pool.count; i++) {
        if (pool.entries[i].pid > 0) {
            kill(pool.entries[i].pid, SIGKILL);
            waitpid(pool.entries[i].pid, NULL, 0);
            gui_post_log(log_target,
                "  Force-killed pool[%d] "
                "(PID %d)",
                i, pool.entries[i].pid);
        }
    }

    memset(&pool, 0, sizeof(pool));

    gui_post_log(log_target,
        "Tor pool stopped");
}