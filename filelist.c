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

#include "filelist.h"
#include "util.h"
#include <dirent.h>

void filelist_add(const char *path)
{
    pthread_mutex_lock(&app.file_mutex);

    if (app.file_count >= MAX_FILES) {
        pthread_mutex_unlock(&app.file_mutex);
        return;
    }

    /* Duplicate check */
    for (int i = 0; i < app.file_count; i++) {
        if (strcmp(app.files[i].path, path) == 0) {
            pthread_mutex_unlock(&app.file_mutex);
            return;
        }
    }

    FileItem *fi = &app.files[app.file_count];
    memset(fi, 0, sizeof(*fi));
    strncpy(fi->path, path, sizeof(fi->path) - 1);

    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    strncpy(fi->name, bn, sizeof(fi->name) - 1);

    struct stat st;
    if (stat(path, &st) == 0) {
        fi->size   = (size_t)st.st_size;
        fi->is_dir = S_ISDIR(st.st_mode);
    }

    app.file_count++;
    pthread_mutex_unlock(&app.file_mutex);
}

void filelist_add_dir(const char *dp)
{
    DIR *d = opendir(dp);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char fp[4096];
        snprintf(fp, sizeof(fp), "%s/%s", dp, e->d_name);

        struct stat st;
        if (stat(fp, &st) == 0 && S_ISREG(st.st_mode))
            filelist_add(fp);
    }

    closedir(d);
}

void filelist_remove(const char *path)
{
    pthread_mutex_lock(&app.file_mutex);

    for (int i = 0; i < app.file_count; i++) {
        if (strcmp(app.files[i].path, path) == 0) {
            memmove(&app.files[i], &app.files[i + 1],
                    (size_t)(app.file_count - i - 1) *
                    sizeof(FileItem));
            app.file_count--;
            break;
        }
    }

    pthread_mutex_unlock(&app.file_mutex);
}

void filelist_clear(void)
{
    pthread_mutex_lock(&app.file_mutex);
    app.file_count = 0;
    pthread_mutex_unlock(&app.file_mutex);
}

void filelist_refresh_view(void)
{
    gtk_list_store_clear(app.share_store);

    pthread_mutex_lock(&app.file_mutex);

    for (int i = 0; i < app.file_count; i++) {
        GtkTreeIter it;
        gtk_list_store_append(app.share_store, &it);

        char sz[64];
        human_size(app.files[i].size, sz, sizeof(sz));

        gtk_list_store_set(app.share_store, &it,
            COL_ICON,   app.files[i].is_dir ?
                        "folder" : "text-x-generic",
            COL_NAME,   app.files[i].name,
            COL_SIZE,   sz,
            COL_PATH,   app.files[i].path,
            COL_STATUS, "Ready",
            -1);
    }

    int n = app.file_count;
    pthread_mutex_unlock(&app.file_mutex);

    if (n == 0) {
        gtk_widget_show(app.share_drag_area);
        gtk_widget_hide(app.share_file_scroll);
    } else {
        gtk_widget_hide(app.share_drag_area);
        gtk_widget_show(app.share_file_scroll);
    }
}