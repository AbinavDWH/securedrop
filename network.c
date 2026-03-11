#include "network.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>

int get_local_addresses(char *buf, size_t bufsz, int port)
{
    struct ifaddrs *ifap = NULL, *ifa;
    size_t off = 0;
    int count = 0;

    if (getifaddrs(&ifap) != 0) {
        snprintf(buf, bufsz, "http://127.0.0.1:%d", port);
        return 1;
    }

    off += (size_t)snprintf(buf + off, bufsz - off,
                            "Listening on port %d:\n", port);

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        char addr[INET6_ADDRSTRLEN];

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa =
                (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr,
                      addr, sizeof(addr));
            if (off < bufsz)
                off += (size_t)snprintf(buf + off, bufsz - off,
                    "  %-10s %s:%d\n",
                    ifa->ifa_name, addr, port);
            count++;
        } else if (ifa->ifa_addr->sa_family == AF_INET6 &&
                   !(ifa->ifa_flags & IFF_LOOPBACK)) {
            struct sockaddr_in6 *sa6 =
                (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr,
                      addr, sizeof(addr));
            if (off < bufsz)
                off += (size_t)snprintf(buf + off, bufsz - off,
                    "  %-10s [%s]:%d\n",
                    ifa->ifa_name, addr, port);
            count++;
        }
    }

    freeifaddrs(ifap);
    return count;
}

void get_primary_ip(char *buf, size_t bufsz)
{
    struct ifaddrs *ifap = NULL, *ifa;
    strncpy(buf, "127.0.0.1", bufsz);

    if (getifaddrs(&ifap) != 0) return;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *sa =
            (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr,
                  buf, (socklen_t)bufsz);
        break;
    }

    freeifaddrs(ifap);
}