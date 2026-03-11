#ifndef NETWORK_H
#define NETWORK_H

#include "app.h"

int  get_local_addresses(char *buf, size_t bufsz, int port);
void get_primary_ip(char *buf, size_t bufsz);

#endif /* NETWORK_H */