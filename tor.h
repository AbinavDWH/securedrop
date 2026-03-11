#ifndef TOR_H
#define TOR_H

#include "app.h"

void        tor_init_circuits(void);
const char *tor_get_next_proxy(void);
int         tor_active_count(void);
void        tor_log_status(int log_target);

#endif /* TOR_H */