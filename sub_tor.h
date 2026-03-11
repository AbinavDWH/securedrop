#ifndef SUB_TOR_H
#define SUB_TOR_H

#include "app.h"

/* Start independent Tor hidden service for one sub-server */
int sub_tor_start(int sub_index, int log_target);

/* Wait for one sub-server's .onion to appear */
int sub_tor_wait(int sub_index, int timeout_sec,
                 int log_target);

/* Start all and wait */
int sub_tor_start_all(int log_target);

/* Stop one */
void sub_tor_stop_one(int sub_index, int log_target);

/* Stop all */
void sub_tor_stop_all(int log_target);

/* Get .onion address for sub-server */
const char *sub_tor_get_onion(int sub_index);

#endif