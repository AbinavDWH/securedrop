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

int sub_tor_start_selected(int count, int log_target);

#endif