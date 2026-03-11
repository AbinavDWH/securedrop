#include "tor.h"

#include <sys/socket.h>
#include <netinet/in.h>

/* Forward declaration */
void gui_post_log(int target, const char *fmt, ...);

/* ── Check if a SOCKS5 port is reachable ───────────────────── */

static int check_socks_port(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Longer timeout — Tor can be slow to respond */
    struct timeval tv = {3, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int ok = (connect(s, (struct sockaddr *)&addr,
                      sizeof(addr)) == 0);
    close(s);
    return ok;
}

/* ── Scan for available Tor SOCKS5 ports ───────────────────── */

void tor_init_circuits(void)
{
    pthread_mutex_lock(&app.circuit_mutex);
    app.num_circuits = 0;

    /* All known Tor SOCKS ports */
    int ports[] = {
        9050,   /* Tor daemon default */
        9150,   /* Tor Browser default */
        9051,   /* Additional instances */
        9052,
        9053,
        9054,
        9055,
        9056,
        9057,
        9058,
        9040,   /* TransPort */
        0       /* sentinel */
    };

    for (int i = 0; ports[i] != 0 &&
                     app.num_circuits < MAX_TOR_CIRCUITS; i++) {
        if (check_socks_port(ports[i])) {
            TorCircuit *tc = &app.circuits[app.num_circuits];
            tc->port   = ports[i];
            tc->active = 1;
            snprintf(tc->proxy, sizeof(tc->proxy),
                     "socks5h://127.0.0.1:%d", ports[i]);
            app.num_circuits++;
        }
    }

    app.next_circuit = 0;
    pthread_mutex_unlock(&app.circuit_mutex);
}

/* ── Round-robin proxy selection ───────────────────────────── */

const char *tor_get_next_proxy(void)
{
    pthread_mutex_lock(&app.circuit_mutex);

    if (app.num_circuits == 0) {
        pthread_mutex_unlock(&app.circuit_mutex);
        /* Return default — caller should verify it works */
        return "socks5h://127.0.0.1:9050";
    }

    const char *p = app.circuits[app.next_circuit].proxy;
    app.next_circuit =
        (app.next_circuit + 1) % app.num_circuits;

    pthread_mutex_unlock(&app.circuit_mutex);
    return p;
}

int tor_active_count(void)
{
    pthread_mutex_lock(&app.circuit_mutex);
    int n = app.num_circuits;
    pthread_mutex_unlock(&app.circuit_mutex);
    return n;
}

void tor_log_status(int log_target)
{
    pthread_mutex_lock(&app.circuit_mutex);

    if (app.num_circuits == 0) {
        gui_post_log(log_target,
            "No Tor circuits detected — "
            "direct connection will be used");
        gui_post_log(log_target,
            "Note: .onion addresses require Tor. "
            "Install: sudo apt install tor");
    } else {
        gui_post_log(log_target,
            "%d Tor circuit(s) available:",
            app.num_circuits);
        for (int i = 0; i < app.num_circuits; i++)
            gui_post_log(log_target,
                "  Circuit %d: socks5h://127.0.0.1:%d",
                i + 1, app.circuits[i].port);
    }

    pthread_mutex_unlock(&app.circuit_mutex);
}