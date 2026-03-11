#ifndef SERVER_H
#define SERVER_H

#include "app.h"

/* Start the main server (handles upload/download/info) */
void server_start(int log_target);

/* Stop the main server */
void server_stop(int log_target);

#endif /* SERVER_H */