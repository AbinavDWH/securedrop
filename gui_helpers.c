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

#include "gui_helpers.h"
#include "util.h"

typedef struct {
    int     target;
    char   *log_msg;
    char   *address;
    char   *file_id;
    double  progress;
    int     downloads;
    int     upd_dl;
} GuiUpdate;

static gboolean gui_idle(gpointer data)
{
    GuiUpdate *u = data;

    GtkTextBuffer *buf = NULL;
    GtkWidget     *prog = NULL;
    GtkWidget     *addr_lbl = NULL;
    GtkWidget     *log_view = NULL;

    switch (u->target) {
    case LOG_SHARE:
        buf = app.share_log_buf;
        prog = app.share_progress;
        addr_lbl = app.share_addr_label;
        log_view = app.share_log_view;
        break;
    case LOG_RECV:
        buf = app.recv_log_buf;
        prog = app.recv_progress;
        log_view = app.recv_log_view;
        break;
    case LOG_SEND:
        buf = app.send_log_buf;
        prog = app.send_progress;
        log_view = app.send_log_view;
        break;
    case LOG_VAULT:
        buf = app.vault_log_buf;
        log_view = app.vault_log_view;
        break;
    case LOG_SERVER:
        buf = app.server_log_buf;
        log_view = app.server_log_view;
        break;
    case LOG_P2P:
        buf = app.p2p_log_buf;
        prog = app.p2p_progress;
        log_view = app.p2p_log_view;
        break;
    case LOG_ADVANCED:
        buf = app.adv_log_buf;
        log_view = app.adv_log_view;
        break;
    }

    /* Append log message */
    if (u->log_msg && buf) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(buf, &end);
        gtk_text_buffer_insert(buf, &end, u->log_msg, -1);

        gtk_text_buffer_get_end_iter(buf, &end);
        GtkTextMark *mark =
            gtk_text_buffer_get_mark(buf, "scroll_end");
        if (!mark)
            mark = gtk_text_buffer_create_mark(buf,
                       "scroll_end", &end, FALSE);
        else
            gtk_text_buffer_move_mark(buf, mark, &end);

        if (log_view)
            gtk_text_view_scroll_to_mark(
                GTK_TEXT_VIEW(log_view),
                mark, 0.0, TRUE, 0.0, 1.0);

        free(u->log_msg);
    }

    /* Update progress bar */
    if (u->progress >= 0.0 && prog)
        gtk_progress_bar_set_fraction(
            GTK_PROGRESS_BAR(prog), u->progress);

    /* Update address label */
    if (u->address && addr_lbl) {
        gtk_label_set_text(GTK_LABEL(addr_lbl), u->address);
        free(u->address);

        /* Stop server animation — server is now active */
        if (u->target == LOG_SHARE && app.server_anim_timer) {
            g_source_remove(app.server_anim_timer);
            app.server_anim_timer = 0;
            if (app.share_server_badge) {
                gtk_widget_set_opacity(
                    app.share_server_badge, 1.0);
                GtkStyleContext *sc =
                    gtk_widget_get_style_context(
                        app.share_server_badge);
                gtk_style_context_remove_class(
                    sc, "server-starting-badge");
                gtk_style_context_add_class(
                    sc, "server-active-badge");
                gtk_label_set_text(
                    GTK_LABEL(app.share_server_badge),
                    "  Server Active  ");
            }
        }
    }

    /* Update download count */
    if (u->upd_dl && app.share_dl_label) {
        char d[64];
        snprintf(d, sizeof(d), "Downloads: %d", u->downloads);
        gtk_label_set_text(GTK_LABEL(app.share_dl_label), d);
    }

    /* Update file ID label */
    if (u->file_id && app.send_fileid_label) {
        gtk_label_set_text(GTK_LABEL(app.send_fileid_label),
                           u->file_id);
        free(u->file_id);
    }

    free(u);
    return G_SOURCE_REMOVE;
}

void gui_post_log(int target, const char *fmt, ...)
{
    va_list ap;
    char *msg = NULL;
    va_start(ap, fmt);
    vasprintf(&msg, fmt, ap);
    va_end(ap);

    char ts[32];
    get_timestamp(ts, sizeof(ts));

    char *full = NULL;
    asprintf(&full, "[%s] %s\n", ts, msg);
    free(msg);

    GuiUpdate *u = calloc(1, sizeof(GuiUpdate));
    u->target   = target;
    u->log_msg  = full;
    u->progress = -1.0;
    g_idle_add(gui_idle, u);
}

void gui_post_progress(int target, double f)
{
    GuiUpdate *u = calloc(1, sizeof(GuiUpdate));
    u->target   = target;
    u->progress = f;
    g_idle_add(gui_idle, u);
}

void gui_post_address(int target, const char *a)
{
    GuiUpdate *u = calloc(1, sizeof(GuiUpdate));
    u->target   = target;
    u->address  = strdup(a);
    u->progress = -1.0;
    g_idle_add(gui_idle, u);
}

void gui_post_downloads(int c)
{
    GuiUpdate *u = calloc(1, sizeof(GuiUpdate));
    u->target    = LOG_SHARE;
    u->upd_dl    = 1;
    u->downloads = c;
    u->progress  = -1.0;
    g_idle_add(gui_idle, u);
}

void gui_post_uploads(int count)
{
    /* Reuse the same mechanism as downloads */
    char msg[128];
    snprintf(msg, sizeof(msg), "Uploads: %d", count);
    gui_post_log(LOG_SERVER, "%s", msg);
}

void gui_post_fileid(const char *file_id)
{
    GuiUpdate *u = calloc(1, sizeof(GuiUpdate));
    u->target   = LOG_SEND;
    u->file_id  = strdup(file_id);
    u->progress = -1.0;
    g_idle_add(gui_idle, u);
}