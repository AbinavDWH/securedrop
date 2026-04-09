/*
 * Veil-Xfer — Encrypted File Sharing over Tor
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