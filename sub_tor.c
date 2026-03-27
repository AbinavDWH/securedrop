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

#include "sub_tor.h"
#include "gui_helpers.h"
#include "util.h"

#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define SUB_TOR_TIMEOUT  180

/* ────────────────────────────────────────────────────────────
   FIND TOR BINARY
   ──────────────────────────────────────────────────────────── */

static int find_tor(char *out, size_t sz)
{
    const char *p[] = {
        "/usr/bin/tor", "/usr/sbin/tor",
        "/usr/local/bin/tor", "/snap/bin/tor",
        NULL
    };

    for (int i = 0; p[i]; i++) {
        if (access(p[i], X_OK) == 0) {
            strncpy(out, p[i], sz - 1);
            out[sz - 1] = '\0';
            return 0;
        }
    }
    return -1;
}

/* ────────────────────────────────────────────────────────────
   CLEAN DATA DIRECTORY

   Remove stale lock files, cached state, and
   old logs that cause Tor to exit immediately.
   Keep the hs/hostname and hs keys so the
   .onion address is reused across restarts.
   ──────────────────────────────────────────────────────────── */

static void clean_tor_datadir(const char *ddir,
                              int log_target)
{
    /* Files that MUST be removed before relaunch */
    const char *stale_files[] = {
        "lock",
        "tor.log",
        "stdout.log",
        "state",
        "cached-certs",
        "cached-consensus",
        "cached-descriptors",
        "cached-descriptors.new",
        "cached-microdesc-consensus",
        "cached-microdescs",
        "cached-microdescs.new",
        "unverified-consensus",
        "unverified-microdesc-consensus",
        "diff-cache",
        NULL
    };

    for (int i = 0; stale_files[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path),
                 "%s/%s", ddir, stale_files[i]);
        unlink(path);  /* ignore errors */
    }

    /* Also remove the key_data directory cache
       that can cause conflicts */
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir),
             "%s/keys", ddir);

    DIR *kd = opendir(keys_dir);
    if (kd) {
        struct dirent *e;
        while ((e = readdir(kd)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char kpath[1024];
            snprintf(kpath, sizeof(kpath),
                     "%s/%s", keys_dir,
                     e->d_name);
            unlink(kpath);
        }
        closedir(kd);
    }
}

/* ────────────────────────────────────────────────────────────
   FIX HS DIRECTORY PERMISSIONS

   Tor REQUIRES HiddenServiceDir to be mode 0700.
   If it's anything else, Tor exits immediately
   with code 1.
   ──────────────────────────────────────────────────────────── */

static void fix_hs_permissions(const char *hsdir)
{
    chmod(hsdir, 0700);

    /* Also fix files inside */
    DIR *d = opendir(hsdir);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path),
                 "%s/%s", hsdir, e->d_name);
        chmod(path, 0600);
    }
    closedir(d);
}

/* ────────────────────────────────────────────────────────────
   READ TOR LOG FOR ERROR DIAGNOSIS
   ──────────────────────────────────────────────────────────── */

static void dump_tor_errors(const char *ddir,
                            int sub_index,
                            int log_target)
{
    char log_path[512];
    snprintf(log_path, sizeof(log_path),
             "%s/tor.log", ddir);

    FILE *f = fopen(log_path, "r");
    if (!f) {
        /* Try stdout.log instead */
        snprintf(log_path, sizeof(log_path),
                 "%s/stdout.log", ddir);
        f = fopen(log_path, "r");
    }
    if (!f) {
        gui_post_log(log_target,
            "  Sub[%d] no log file found",
            sub_index);
        return;
    }

    char line[1024];
    int printed = 0;

    while (fgets(line, sizeof(line), f) &&
           printed < 5) {
        /* Show error/warning lines */
        if (strstr(line, "[err]") ||
            strstr(line, "[warn]") ||
            strstr(line, "Permission denied") ||
            strstr(line, "Cannot") ||
            strstr(line, "Failed") ||
            strstr(line, "lock") ||
            strstr(line, "already running")) {

            /* Trim newline */
            size_t len = strlen(line);
            while (len > 0 &&
                   (line[len - 1] == '\n' ||
                    line[len - 1] == '\r'))
                line[--len] = '\0';

            gui_post_log(log_target,
                "  Sub[%d] LOG: %s",
                sub_index, line);
            printed++;
        }
    }

    fclose(f);

    if (printed == 0) {
        gui_post_log(log_target,
            "  Sub[%d] no error lines in log",
            sub_index);
    }
}

/* ────────────────────────────────────────────────────────────
   CHECK TOR LOG FOR HS DESCRIPTOR UPLOAD
   ──────────────────────────────────────────────────────────── */

static int check_hs_published(const char *ddir)
{
    char log_path[512];
    snprintf(log_path, sizeof(log_path),
             "%s/tor.log", ddir);

    FILE *f = fopen(log_path, "r");
    if (!f) return 0;

    char line[1024];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line,
                "Uploaded rendezvous "
                "descriptor") ||
            strstr(line,
                "Successfully uploaded") ||
            strstr(line,
                "upload rendezvous desc") ||
            strstr(line,
                "Descriptor uploaded") ||
            strstr(line,
                "hs_service_upload_desc")) {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

/* ────────────────────────────────────────────────────────────
   CHECK TOR LOG FOR BOOTSTRAP COMPLETE
   ──────────────────────────────────────────────────────────── */

static int check_bootstrapped(const char *ddir)
{
    char log_path[512];
    snprintf(log_path, sizeof(log_path),
             "%s/tor.log", ddir);

    FILE *f = fopen(log_path, "r");
    if (!f) return 0;

    char line[1024];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Bootstrapped 100%")) {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

/* ────────────────────────────────────────────────────────────
   START INDEPENDENT TOR FOR ONE SUB-SERVER
   ──────────────────────────────────────────────────────────── */

int sub_tor_start(int sub_index, int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);

    if (sub_index < 0 ||
        sub_index >= app.num_sub_servers) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return -1;
    }

    SubServer *ss = &app.sub_servers[sub_index];

    if (!ss->active) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        gui_post_log(log_target,
            "Sub[%d] not active, "
            "skipping Tor", sub_index);
        return -1;
    }

    if (ss->tor_pid > 0) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return 0;
    }

    int port = ss->port;
    pthread_mutex_unlock(&app.subserver_mutex);

    char tor_bin[512];
    if (find_tor(tor_bin,
                 sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor binary not found");
        return -1;
    }

    /* ── Create directories ──────────────────── */

    char ddir[256];
    snprintf(ddir, sizeof(ddir),
             "tor_data/sub_%d", sub_index);
    mkdir_p(ddir, 0700);
    chmod(ddir, 0700);

    char hsdir[300];
    snprintf(hsdir, sizeof(hsdir),
             "%s/hs", ddir);
    mkdir_p(hsdir, 0700);

    /* ── Clean stale files ───────────────────── */

    clean_tor_datadir(ddir, log_target);
    fix_hs_permissions(hsdir);

    /* ── Write torrc ─────────────────────────── */

    char torrc[300];
    snprintf(torrc, sizeof(torrc),
             "%s/torrc", ddir);

    FILE *fp = fopen(torrc, "w");
    if (!fp) {
        gui_post_log(log_target,
            "Sub[%d] cannot create torrc",
            sub_index);
        return -1;
    }

    /*
     * Key points in this torrc:
     *
     * SocksPort 0    — no SOCKS listener
     *                  (this is a server, not
     *                   a client proxy)
     *
     * DataDirectory  — unique per sub-server
     *                  MUST NOT overlap with
     *                  main Tor or other subs
     *
     * HiddenServiceDir — unique, mode 0700
     *
     * Log notice file — fresh log for error
     *                   diagnosis
     *
     * RunAsDaemon 0  — stay in foreground so
     *                  we can track the PID
     *
     * No shared state with main Tor instance
     */

    fprintf(fp,
        "# Sub-server %d — independent Tor\n"
        "SocksPort 0\n"
        "RunAsDaemon 0\n"
        "DataDirectory %s\n"
        "HiddenServiceDir %s\n"
        "HiddenServicePort 80 127.0.0.1:%d\n"
        "Log notice file %s/tor.log\n"
        "AvoidDiskWrites 1\n"
        "\n"
        "# Allow multiple Tor instances\n"
        "# Each has unique DataDirectory so\n"
        "# no lock conflicts\n"
        "\n"
        "# HS tuning\n"
        "HiddenServiceMaxStreams 64\n"
        "HiddenServiceMaxStreamsCloseCircuit 0\n",
        sub_index, ddir, hsdir, port, ddir);

    fclose(fp);

    /* ── Verify directory permissions ────────── */

    struct stat st;
    if (stat(hsdir, &st) == 0) {
        if ((st.st_mode & 0777) != 0700) {
            gui_post_log(log_target,
                "Sub[%d] fixing hs dir "
                "permissions: %o → 700",
                sub_index,
                st.st_mode & 0777);
            chmod(hsdir, 0700);
        }
    }

    if (stat(ddir, &st) == 0) {
        if ((st.st_mode & 0777) != 0700) {
            chmod(ddir, 0700);
        }
    }

    /* ── Fork Tor ────────────────────────────── */

    pid_t pid = fork();

    if (pid < 0) {
        gui_post_log(log_target,
            "Sub[%d] fork failed", sub_index);
        return -1;
    }

    if (pid == 0) {
        /* Child — redirect stdout/stderr */
        char logp[300];
        snprintf(logp, sizeof(logp),
                 "%s/stdout.log", ddir);
        int fd = open(logp,
            O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }

        /* Close inherited file descriptors
           (especially MHD sockets!) */
        for (int f = 3; f < 1024; f++)
            close(f);

        execl(tor_bin, "tor",
              "-f", torrc, NULL);
        _exit(127);
    }

    /* Parent */
    pthread_mutex_lock(&app.subserver_mutex);
    ss->tor_pid = pid;
    strncpy(ss->tor_datadir, ddir,
            sizeof(ss->tor_datadir) - 1);
    ss->tor_ready = 0;
    ss->onion_addr[0] = '\0';
    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "Sub[%d] Tor launched "
        "(PID %d, port %d)",
        sub_index, pid, port);

    return 0;
}

/* ────────────────────────────────────────────────────────────
   WAIT FOR ONE SUB-SERVER'S .ONION

   Three-phase readiness:
     Phase 0: waiting for hostname file
     Phase 1: waiting for bootstrap 100%
     Phase 2: waiting for HS descriptor upload
   ──────────────────────────────────────────────────────────── */

int sub_tor_wait(int sub_index, int timeout_sec,
                 int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);

    if (sub_index < 0 ||
        sub_index >= app.num_sub_servers) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return -1;
    }

    SubServer *ss = &app.sub_servers[sub_index];

    if (ss->tor_ready) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return 0;
    }

    char ddir[256];
    strncpy(ddir, ss->tor_datadir,
            sizeof(ddir) - 1);
    ddir[sizeof(ddir) - 1] = '\0';
    pid_t pid = ss->tor_pid;
    pthread_mutex_unlock(&app.subserver_mutex);

    char hostname_path[400];
    snprintf(hostname_path,
             sizeof(hostname_path),
             "%s/hs/hostname", ddir);

    time_t start = time(NULL);
    int phase = 0;
    char onion_buf[256] = {0};

    while (time(NULL) - start < timeout_sec) {
        /* Check if process died */
        if (pid > 0) {
            int status;
            pid_t r = waitpid(pid, &status,
                              WNOHANG);
            if (r > 0) {
                int exit_code =
                    WIFEXITED(status) ?
                    WEXITSTATUS(status) : -1;

                gui_post_log(log_target,
                    "Sub[%d] Tor died "
                    "(exit code %d)",
                    sub_index, exit_code);

                /* Dump the actual error */
                dump_tor_errors(ddir,
                    sub_index, log_target);

                return -1;
            }
        }

        if (phase == 0) {
            FILE *fp =
                fopen(hostname_path, "r");
            if (fp) {
                if (fgets(onion_buf,
                    sizeof(onion_buf), fp)) {

                    size_t len =
                        strlen(onion_buf);
                    while (len > 0 &&
                        (onion_buf[len-1] == '\n'
                        || onion_buf[len-1] == '\r'
                        || onion_buf[len-1] == ' '))
                        onion_buf[--len] = '\0';

                    if (len > 6 &&
                        strstr(onion_buf,
                               ".onion")) {
                        gui_post_log(log_target,
                            "  Sub[%d] hostname "
                            "created: %.20s...",
                            sub_index, onion_buf);
                        phase = 1;
                    }
                }
                fclose(fp);
            }
        }

        if (phase == 1) {
            if (check_bootstrapped(ddir)) {
                gui_post_log(log_target,
                    "  Sub[%d] bootstrapped",
                    sub_index);
                phase = 2;
            }
        }

        if (phase == 2) {
            if (check_hs_published(ddir)) {
                gui_post_log(log_target,
                    "\xE2\x9C\x93 Sub[%d] "
                    "PUBLISHED: %.20s..."
                    "onion",
                    sub_index, onion_buf);

                pthread_mutex_lock(
                    &app.subserver_mutex);
                strncpy(ss->onion_addr,
                    onion_buf,
                    sizeof(ss->onion_addr) - 1);
                ss->tor_ready = 1;
                pthread_mutex_unlock(
                    &app.subserver_mutex);

                return 0;
            }
        }

        usleep(500000);
    }

    /* Timeout fallback */
    if (phase >= 1 && onion_buf[0] != '\0') {
        gui_post_log(log_target,
            "\xE2\x9A\xA0 Sub[%d] HS not "
            "confirmed but hostname ready",
            sub_index);

        pthread_mutex_lock(
            &app.subserver_mutex);
        strncpy(ss->onion_addr, onion_buf,
            sizeof(ss->onion_addr) - 1);
        ss->tor_ready = 1;
        pthread_mutex_unlock(
            &app.subserver_mutex);

        return 0;
    }

    gui_post_log(log_target,
        "Sub[%d] Tor timeout (phase %d)",
        sub_index, phase);

    /* Dump errors on timeout too */
    dump_tor_errors(ddir, sub_index, log_target);

    return -1;
}

/* ────────────────────────────────────────────────────────────
   START ALL AND WAIT
   ──────────────────────────────────────────────────────────── */

typedef struct {
    int sub_index;
    int log_target;
} SubTorWaitArg;

static void *wait_thread(void *arg)
{
    SubTorWaitArg *a = arg;
    sub_tor_wait(a->sub_index, SUB_TOR_TIMEOUT,
                 a->log_target);
    free(a);
    return NULL;
}

int sub_tor_start_all(int log_target)
{
    char tor_bin[512];
    if (find_tor(tor_bin,
                 sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor not found — sub-servers "
            "LAN-only");
        return 0;
    }

    pthread_mutex_lock(&app.subserver_mutex);
    int n = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    if (n == 0) return 0;

    /* Cap at reasonable number to avoid
       overwhelming the system */
        int max_tor = app.user_tor_count;
    if (max_tor <= 0) max_tor = n;
    if (max_tor > n) max_tor = n;
    if (max_tor > MAX_SUB_SERVERS) max_tor = MAX_SUB_SERVERS;
    n = max_tor;

    gui_post_log(log_target,
        "══════════════════════════"
        "═══════════");
    gui_post_log(log_target,
        "Starting %d independent Tor "
        "hidden services...", n);
    gui_post_log(log_target,
        "Each sub-server gets its own "
        ".onion");
    gui_post_log(log_target,
        "Cleaning stale state from "
        "previous runs...");
    gui_post_log(log_target,
        "══════════════════════════"
        "═══════════");

    /* Launch all Tor processes with stagger */
    int launched = 0;
    for (int i = 0; i < n; i++) {
        if (sub_tor_start(i, log_target) == 0)
            launched++;
        else
            gui_post_log(log_target,
                "  Sub[%d] launch failed", i);

        /* 1 second stagger between launches
           to reduce simultaneous load */
        if (i < n - 1)
            usleep(1000000);
    }

    if (launched == 0) {
        gui_post_log(log_target,
            "No sub-server Tor instances "
            "started");
        return 0;
    }

    gui_post_log(log_target,
        "Launched %d Tor instances, "
        "waiting for HS publication "
        "(up to %ds)...",
        launched, SUB_TOR_TIMEOUT);

    /* Wait for all in parallel */
    pthread_t *threads = malloc(
        (size_t)n * sizeof(pthread_t));
    int *thread_valid = calloc(
        (size_t)n, sizeof(int));

    for (int i = 0; i < n; i++) {
        pthread_mutex_lock(
            &app.subserver_mutex);
        int has_tor =
            (app.sub_servers[i].tor_pid > 0);
        pthread_mutex_unlock(
            &app.subserver_mutex);

        if (!has_tor) continue;

        SubTorWaitArg *a = malloc(sizeof(*a));
        a->sub_index = i;
        a->log_target = log_target;

        pthread_create(&threads[i], NULL,
                       wait_thread, a);
        thread_valid[i] = 1;
    }

    for (int i = 0; i < n; i++) {
        if (thread_valid[i])
            pthread_join(threads[i], NULL);
    }

    free(threads);
    free(thread_valid);

    /* Count ready */
    int ready = 0;
    pthread_mutex_lock(&app.subserver_mutex);
    for (int i = 0;
         i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].tor_ready)
            ready++;
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "══════════════════════════"
        "═══════════");
    gui_post_log(log_target,
        "%d/%d sub-server .onion "
        "services PUBLISHED", ready, n);

    if (ready > 0) {
        gui_post_log(log_target,
            "Each chunk travels through "
            "INDEPENDENT Tor circuit");
        gui_post_log(log_target,
            "Expected speed: "
            "~%d\xC3\x97 single circuit",
            ready);
    }

    if (ready < n) {
        gui_post_log(log_target,
            "\xE2\x9A\xA0 %d services "
            "failed — will use %d "
            "for parallel",
            n - ready, ready);
    }

    gui_post_log(log_target,
        "══════════════════════════"
        "═══════════");

    return ready;
}

/* ────────────────────────────────────────────────────────────
   GET .ONION ADDRESS
   ──────────────────────────────────────────────────────────── */

const char *sub_tor_get_onion(int sub_index)
{
    pthread_mutex_lock(&app.subserver_mutex);

    if (sub_index < 0 ||
        sub_index >= app.num_sub_servers) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return NULL;
    }

    SubServer *ss =
        &app.sub_servers[sub_index];

    if (!ss->tor_ready ||
        ss->onion_addr[0] == '\0') {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return NULL;
    }

    const char *addr = ss->onion_addr;
    pthread_mutex_unlock(&app.subserver_mutex);

    return addr;
}

/* ────────────────────────────────────────────────────────────
   STOP ONE
   ──────────────────────────────────────────────────────────── */

void sub_tor_stop_one(int sub_index,
                      int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);

    if (sub_index < 0 ||
        sub_index >= app.num_sub_servers) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return;
    }

    SubServer *ss =
        &app.sub_servers[sub_index];
    pid_t pid = ss->tor_pid;

    if (pid <= 0) {
        pthread_mutex_unlock(
            &app.subserver_mutex);
        return;
    }

    ss->tor_pid = 0;
    ss->tor_ready = 0;
    ss->onion_addr[0] = '\0';
    pthread_mutex_unlock(&app.subserver_mutex);

    kill(pid, SIGTERM);

    for (int i = 0; i < 10; i++) {
        int status;
        pid_t r = waitpid(pid, &status,
                          WNOHANG);
        if (r > 0) return;
        usleep(500000);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

/* ────────────────────────────────────────────────────────────
   STOP ALL
   ──────────────────────────────────────────────────────────── */

void sub_tor_stop_all(int log_target)
{
    pthread_mutex_lock(&app.subserver_mutex);
    int n = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "Stopping %d sub-server Tor "
        "instances...", n);

    /* SIGTERM all first */
    pthread_mutex_lock(&app.subserver_mutex);
    for (int i = 0; i < n; i++) {
        if (app.sub_servers[i].tor_pid > 0)
            kill(app.sub_servers[i].tor_pid,
                 SIGTERM);
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    usleep(3000000);

    /* Cleanup */
    for (int i = 0; i < n; i++) {
        pthread_mutex_lock(
            &app.subserver_mutex);
        pid_t pid =
            app.sub_servers[i].tor_pid;
        pthread_mutex_unlock(
            &app.subserver_mutex);

        if (pid > 0) {
            int status;
            pid_t r = waitpid(pid, &status,
                              WNOHANG);
            if (r <= 0) {
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
            }
        }

        pthread_mutex_lock(
            &app.subserver_mutex);
        app.sub_servers[i].tor_pid = 0;
        app.sub_servers[i].tor_ready = 0;
        app.sub_servers[i].onion_addr[0] = '\0';
        pthread_mutex_unlock(
            &app.subserver_mutex);
    }

    gui_post_log(log_target,
        "All sub-server Tor instances "
        "stopped");


        
}

int sub_tor_start_selected(int count, int log_target)
{
    char tor_bin[512];
    if (find_tor(tor_bin, sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor not found — sub-servers LAN-only");
        return 0;
    }

    pthread_mutex_lock(&app.subserver_mutex);
    int n = app.num_sub_servers;
    pthread_mutex_unlock(&app.subserver_mutex);

    if (n == 0) return 0;
    if (count <= 0) count = n;
    if (count > n) count = n;
    if (count > 64) count = 64;

    gui_post_log(log_target,
        "══════════════════════════════════════");
    gui_post_log(log_target,
        "Starting %d independent Tor hidden services...",
        count);
    gui_post_log(log_target,
        "Each sub-server gets its own .onion address");
    gui_post_log(log_target,
        "══════════════════════════════════════");

    int launched = 0;
    for (int i = 0; i < count; i++) {
        if (sub_tor_start(i, log_target) == 0)
            launched++;
        else
            gui_post_log(log_target,
                "  Sub[%d] launch failed", i);

        if (i < count - 1)
            usleep(1000000);
    }

    if (launched == 0) {
        gui_post_log(log_target,
            "No sub-server Tor instances started");
        return 0;
    }

    gui_post_log(log_target,
        "Launched %d Tor instances, waiting for "
        "HS publication (up to %ds)...",
        launched, SUB_TOR_TIMEOUT);

    pthread_t *threads = malloc(
        (size_t)count * sizeof(pthread_t));
    int *thread_valid = calloc(
        (size_t)count, sizeof(int));

    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&app.subserver_mutex);
        int has_tor = (app.sub_servers[i].tor_pid > 0);
        pthread_mutex_unlock(&app.subserver_mutex);

        if (!has_tor) continue;

        SubTorWaitArg *a = malloc(sizeof(*a));
        a->sub_index = i;
        a->log_target = log_target;

        pthread_create(&threads[i], NULL,
                       wait_thread, a);
        thread_valid[i] = 1;
    }

    for (int i = 0; i < count; i++) {
        if (thread_valid[i])
            pthread_join(threads[i], NULL);
    }

    free(threads);
    free(thread_valid);

    int ready = 0;
    pthread_mutex_lock(&app.subserver_mutex);
    for (int i = 0; i < app.num_sub_servers; i++) {
        if (app.sub_servers[i].tor_ready)
            ready++;
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    gui_post_log(log_target,
        "══════════════════════════════════════");
    gui_post_log(log_target,
        "%d/%d sub-server .onion services ready",
        ready, count);
    gui_post_log(log_target,
        "══════════════════════════════════════");

    return ready;
}