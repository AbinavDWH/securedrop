#include "onion.h"
#include "gui_helpers.h"
#include "util.h"

#include <signal.h>
#include <sys/wait.h>

/* Shorthand */
#define ON app.onion

/* ────────────────────────────────────────────────────────────
   FIND TOR BINARY
   ──────────────────────────────────────────────────────────── */

static int find_tor_binary(char *out, size_t sz)
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

    /* Try PATH */
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
   WRITE TORRC WITH MULTIPLE PORTS
   ──────────────────────────────────────────────────────────── */

static int write_torrc(int main_port,
                       const int *sub_ports,
                       int num_sub_ports,
                       int log_target)
{
    /* Setup directories */
    snprintf(ON.data_dir, sizeof(ON.data_dir),
             "%s", TOR_DATA_DIR);
    mkdir_p(ON.data_dir, 0700);
    mkdir_p(TOR_HS_DIR, 0700);

    snprintf(ON.torrc_path, sizeof(ON.torrc_path),
             "%s/torrc", ON.data_dir);

    FILE *fp = fopen(ON.torrc_path, "w");
    if (!fp) {
        gui_post_log(log_target,
            "Cannot create torrc: %s",
            ON.torrc_path);
        return -1;
    }

    /* Basic config */
    fprintf(fp,
        "# SecureDrop auto-generated torrc\n"
        "SocksPort 0\n"
        "DataDirectory %s\n"
        "HiddenServiceDir %s\n",
        ON.data_dir, TOR_HS_DIR);

    /* Main server port */
    fprintf(fp,
        "HiddenServicePort %d 127.0.0.1:%d\n",
        ONION_VIRTUAL_PORT, main_port);

    gui_post_log(log_target,
        "Torrc: port %d → 127.0.0.1:%d (main)",
        ONION_VIRTUAL_PORT, main_port);

    /* Sub-server ports — each gets its own
       HiddenServicePort line on the SAME .onion */
    for (int i = 0; i < num_sub_ports; i++) {
        fprintf(fp,
            "HiddenServicePort %d 127.0.0.1:%d\n",
            sub_ports[i], sub_ports[i]);
    }

    if (num_sub_ports > 0) {
        gui_post_log(log_target,
            "Torrc: %d sub-server ports "
            "(%d–%d) added to hidden service",
            num_sub_ports,
            sub_ports[0],
            sub_ports[num_sub_ports - 1]);
    }

    /* Logging */
    fprintf(fp,
        "Log notice file %s/tor.log\n",
        ON.data_dir);

    fclose(fp);

    ON.virtual_port = ONION_VIRTUAL_PORT;
    ON.local_port   = main_port;

    return 0;
}

/* ────────────────────────────────────────────────────────────
   START TOR PROCESS (internal)
   ──────────────────────────────────────────────────────────── */

static int start_tor_process(int log_target)
{
    char tor_bin[512];
    if (find_tor_binary(tor_bin, sizeof(tor_bin)) != 0) {
        gui_post_log(log_target,
            "Tor binary not found. Install:");
        gui_post_log(log_target,
            "  sudo apt install tor");
        return -1;
    }

    gui_post_log(log_target,
        "Tor binary: %s", tor_bin);
    gui_post_log(log_target,
        "Torrc: %s", ON.torrc_path);

    pid_t pid = fork();
    if (pid < 0) {
        gui_post_log(log_target, "Fork failed");
        return -1;
    }

    if (pid == 0) {
        /* Child — exec tor */

        /* Redirect stdout/stderr to log */
        char log_path[512];
        snprintf(log_path, sizeof(log_path),
                 "%s/tor_stdout.log", ON.data_dir);

        int fd = open(log_path,
                      O_WRONLY | O_CREAT | O_TRUNC,
                      0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }

        /* Close all other FDs */
        for (int i = 3; i < 1024; i++)
            close(i);

        execlp(tor_bin, "tor",
               "-f", ON.torrc_path,
               NULL);

        _exit(127);
    }

    /* Parent */
    ON.tor_pid = pid;
    ON.running = 1;

    gui_post_log(log_target,
        "Tor started (PID %d)", pid);

    return 0;
}

/* ────────────────────────────────────────────────────────────
   PUBLIC: START WITH MAIN PORT ONLY
   ──────────────────────────────────────────────────────────── */

int onion_start(int local_port, int log_target)
{
    return onion_start_with_ports(
        local_port, NULL, 0, log_target);
}

/* ────────────────────────────────────────────────────────────
   PUBLIC: START WITH MAIN + SUB-SERVER PORTS
   ──────────────────────────────────────────────────────────── */

int onion_start_with_ports(int main_port,
                           const int *sub_ports,
                           int num_sub_ports,
                           int log_target)
{
    if (ON.running) {
        gui_post_log(log_target,
            "Tor already running (PID %d)",
            ON.tor_pid);
        return 0;
    }

    memset(&ON, 0, sizeof(ON));

    gui_post_log(log_target,
        "Configuring Tor hidden service...");
    gui_post_log(log_target,
        "  Main port: %d → virtual port %d",
        main_port, ONION_VIRTUAL_PORT);

    if (num_sub_ports > 0) {
        gui_post_log(log_target,
            "  Sub-server ports: %d "
            "(range %d–%d)",
            num_sub_ports,
            sub_ports[0],
            sub_ports[num_sub_ports - 1]);
    }

    /* Write torrc with all ports */
    if (write_torrc(main_port, sub_ports,
                    num_sub_ports, log_target) != 0)
        return -1;

    /* Start tor process */
    return start_tor_process(log_target);
}

/* ────────────────────────────────────────────────────────────
   WAIT FOR .ONION ADDRESS
   ──────────────────────────────────────────────────────────── */

int onion_wait_for_address(int timeout_sec,
                           int log_target)
{
    char hostname_path[512];
    snprintf(hostname_path, sizeof(hostname_path),
             "%s/hostname", TOR_HS_DIR);

    gui_post_log(log_target,
        "Waiting for onion address "
        "(timeout %ds)...", timeout_sec);

    time_t start = time(NULL);

    while (time(NULL) - start < timeout_sec) {
        /* Check if tor process died */
        if (ON.tor_pid > 0) {
            int status;
            pid_t r = waitpid(ON.tor_pid, &status,
                              WNOHANG);
            if (r > 0) {
                gui_post_log(log_target,
                    "Tor process exited "
                    "(status %d)", status);

                /* Try to show tor log */
                char log_path[512];
                snprintf(log_path, sizeof(log_path),
                         "%s/tor.log", ON.data_dir);
                FILE *lf = fopen(log_path, "r");
                if (lf) {
                    char line[512];
                    int lines = 0;
                    /* Show last few lines */
                    while (fgets(line, sizeof(line),
                                 lf)) {
                        lines++;
                    }
                    fseek(lf, 0, SEEK_SET);
                    int skip = lines > 10 ?
                               lines - 10 : 0;
                    int n = 0;
                    while (fgets(line, sizeof(line),
                                 lf)) {
                        if (n++ >= skip) {
                            size_t ll = strlen(line);
                            if (ll > 0 &&
                                line[ll-1] == '\n')
                                line[ll-1] = '\0';
                            gui_post_log(log_target,
                                "  tor: %s", line);
                        }
                    }
                    fclose(lf);
                }

                ON.running = 0;
                return -1;
            }
        }

        /* Check for hostname file */
        FILE *fp = fopen(hostname_path, "r");
        if (fp) {
            char addr[256];
            if (fgets(addr, sizeof(addr), fp)) {
                fclose(fp);

                /* Trim whitespace */
                size_t len = strlen(addr);
                while (len > 0 &&
                       (addr[len-1] == '\n' ||
                        addr[len-1] == '\r' ||
                        addr[len-1] == ' '))
                    addr[--len] = '\0';

                if (len > 6 &&
                    strstr(addr, ".onion")) {

                    strncpy(ON.onion_address, addr,
                            sizeof(ON.onion_address) - 1);

                    snprintf(ON.full_address,
                             sizeof(ON.full_address),
                             "%s:%d",
                             ON.onion_address,
                             ON.virtual_port);

                    gui_post_log(log_target,
                        "Onion address ready: %s",
                        ON.full_address);

                    return 0;
                }
            } else {
                fclose(fp);
            }
        }

        /* Progress indicator */
        int elapsed = (int)(time(NULL) - start);
        if (elapsed > 0 && elapsed % 10 == 0) {
            gui_post_log(log_target,
                "  Still waiting... (%ds/%ds)",
                elapsed, timeout_sec);
        }

        usleep(500000);  /* 0.5 seconds */
    }

    gui_post_log(log_target,
        "Timeout waiting for onion address");
    return -1;
}

/* ────────────────────────────────────────────────────────────
   GET FULL ADDRESS (with port)
   Returns "xyz.onion:80" or NULL
   ──────────────────────────────────────────────────────────── */

const char *onion_get_full_address(void)
{
    if (ON.full_address[0] != '\0')
        return ON.full_address;
    return NULL;
}

/* ────────────────────────────────────────────────────────────
   GET HOSTNAME ONLY (no port)
   Returns "xyz.onion" or NULL
   ──────────────────────────────────────────────────────────── */

const char *onion_get_hostname(void)
{
    if (ON.onion_address[0] != '\0')
        return ON.onion_address;
    return NULL;
}

/* ────────────────────────────────────────────────────────────
   STOP TOR
   ──────────────────────────────────────────────────────────── */

void onion_stop(int log_target)
{
    if (!ON.running || ON.tor_pid <= 0) {
        ON.running = 0;
        return;
    }

    gui_post_log(log_target,
        "Stopping Tor (PID %d)...", ON.tor_pid);

    /* Send SIGTERM first */
    kill(ON.tor_pid, SIGTERM);

    /* Wait up to 10 seconds */
    for (int i = 0; i < 20; i++) {
        int status;
        pid_t r = waitpid(ON.tor_pid, &status,
                          WNOHANG);
        if (r > 0) {
            gui_post_log(log_target,
                "Tor stopped (PID %d)", ON.tor_pid);
            goto cleanup;
        }
        usleep(500000);
    }

    /* Force kill */
    gui_post_log(log_target,
        "Force-killing Tor (PID %d)", ON.tor_pid);
    kill(ON.tor_pid, SIGKILL);
    waitpid(ON.tor_pid, NULL, 0);

cleanup:
    ON.tor_pid = 0;
    ON.running = 0;
    ON.onion_address[0] = '\0';
    ON.full_address[0]  = '\0';

    gui_post_log(log_target, "Tor hidden service stopped");
}