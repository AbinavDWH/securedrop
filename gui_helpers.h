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

#ifndef GUI_HELPERS_H
#define GUI_HELPERS_H

#include "app.h"

void gui_post_log(int target, const char *fmt, ...);
void gui_post_progress(int target, double fraction);
void gui_post_address(int target, const char *address);
void gui_post_downloads(int count);
void gui_post_fileid(const char *file_id);
void gui_post_uploads(int count);


#endif /* GUI_HELPERS_H */