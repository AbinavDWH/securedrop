#ifndef ONION_H
#define ONION_H

#include "app.h"

/* Start Tor with main port only */
int onion_start(int local_port, int log_target);

/* Start Tor with main port + sub-server ports */
int onion_start_with_ports(int main_port,
                           const int *sub_ports,
                           int num_sub_ports,
                           int log_target);

/* Wait for .onion hostname file to appear */
int onion_wait_for_address(int timeout_sec,
                           int log_target);

/* Get "xyz.onion:80" */
const char *onion_get_full_address(void);

/* Get just "xyz.onion" (no port) */
const char *onion_get_hostname(void);

/* Stop Tor process */
void onion_stop(int log_target);

#endif /* ONION_H */