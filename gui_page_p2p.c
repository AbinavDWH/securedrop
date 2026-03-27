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

#include "gui_page_p2p.h"
#include "gui_helpers.h"
#include "p2p.h"
#include "util.h"

static GtkWidget *mkbtn(const char *label,
                        const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* ── Callbacks ─────────────────────────────────────────────── */

static void on_p2p_start(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    char *filepath = gtk_file_chooser_get_filename(
        GTK_FILE_CHOOSER(app.p2p_send_file_btn));
    if (!filepath || !*filepath) {
        gui_post_log(LOG_P2P,
            "Select a file first");
        g_free(filepath);
        return;
    }

    const char *password = gtk_entry_get_text(
        GTK_ENTRY(app.p2p_send_password_entry));
    if (!password || strlen(password) < 4) {
        gui_post_log(LOG_P2P,
            "Password must be at least "
            "4 characters");
        g_free(filepath);
        return;
    }

    const char *subs_str = gtk_entry_get_text(
        GTK_ENTRY(app.p2p_send_subs_entry));
    int num_subs = 16;
    if (subs_str && *subs_str)
        num_subs = atoi(subs_str);
    if (num_subs < 1 || num_subs > 128) {
        gui_post_log(LOG_P2P,
            "Sub-servers must be 1–128");
        g_free(filepath);
        return;
    }

    gui_post_progress(LOG_P2P, 0.0);
    p2p_start_sender(filepath, password,
                     num_subs, LOG_P2P);

    gtk_widget_set_sensitive(
        app.p2p_start_btn, FALSE);
    gtk_widget_set_sensitive(
        app.p2p_stop_btn, TRUE);

    g_free(filepath);
}

static void on_p2p_stop(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    p2p_stop_sender(LOG_P2P);

    gtk_widget_set_sensitive(
        app.p2p_start_btn, TRUE);
    gtk_widget_set_sensitive(
        app.p2p_stop_btn, FALSE);

    gtk_label_set_text(
        GTK_LABEL(app.p2p_send_status_label),
        "Not running");
}

static void on_p2p_recv(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    const char *addr = gtk_entry_get_text(
        GTK_ENTRY(app.p2p_recv_addr_entry));
    if (!addr || !*addr) {
        gui_post_log(LOG_P2P,
            "Enter the sender's address "
            "(IP:port)");
        return;
    }

    const char *password = gtk_entry_get_text(
        GTK_ENTRY(app.p2p_recv_password_entry));
    if (!password || strlen(password) < 4) {
        gui_post_log(LOG_P2P,
            "Password must be at least "
            "4 characters");
        return;
    }

    gui_post_log(LOG_P2P,
        "Starting P2P receive...");
    gui_post_progress(LOG_P2P, 0.0);

    p2p_receive_file(addr, password, LOG_P2P);
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_p2p_page(void)
{
    GtkWidget *page = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(
        GTK_CONTAINER(page), 20);

    /* ── Header ──────────────────────────────────── */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<b>P2P Transfer</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title),
        "sec-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page),
        title, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new(
        "Direct peer-to-peer encrypted file "
        "transfer. No server needed \xe2\x80\x94 "
        "one peer sends, the other receives.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub),
        "page-subtitle");
    gtk_widget_set_halign(sub, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(sub), TRUE);
    gtk_box_pack_start(GTK_BOX(page),
        sub, FALSE, FALSE, 0);
    /* ── Send Section ─────────────────────────── */
    GtkWidget *send_hdr = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(send_hdr),
        "<b>Send a File</b>");
    gtk_widget_set_halign(send_hdr, GTK_ALIGN_START);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(send_hdr), "sec-title");
    gtk_box_pack_start(GTK_BOX(page),
        send_hdr, FALSE, FALSE, 4);

    /* Send grid */
    GtkWidget *sg = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(sg), 8);
    gtk_grid_set_column_spacing(GTK_GRID(sg), 10);

    /* File chooser */
    GtkWidget *fl = gtk_label_new("File:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(fl), "dim-text");
    gtk_widget_set_halign(fl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(sg), fl, 0, 0, 1, 1);

    app.p2p_send_file_btn =
        gtk_file_chooser_button_new(
            "Select File",
            GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_widget_set_hexpand(
        app.p2p_send_file_btn, TRUE);
    gtk_grid_attach(GTK_GRID(sg),
        app.p2p_send_file_btn, 1, 0, 2, 1);

    /* Password */
    GtkWidget *pl = gtk_label_new("Password:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(pl), "dim-text");
    gtk_widget_set_halign(pl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(sg), pl, 0, 1, 1, 1);

    app.p2p_send_password_entry = gtk_entry_new();
    gtk_entry_set_visibility(
        GTK_ENTRY(app.p2p_send_password_entry),
        FALSE);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.p2p_send_password_entry),
        "Shared password for this transfer");
    gtk_entry_set_input_purpose(
        GTK_ENTRY(app.p2p_send_password_entry),
        GTK_INPUT_PURPOSE_PASSWORD);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(
            app.p2p_send_password_entry),
        "pwd-entry");
    gtk_widget_set_hexpand(
        app.p2p_send_password_entry, TRUE);
    gtk_grid_attach(GTK_GRID(sg),
        app.p2p_send_password_entry, 1, 1, 2, 1);

    /* Sub-servers */
    GtkWidget *ptl = gtk_label_new("Subs:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(ptl), "dim-text");
    gtk_widget_set_halign(ptl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(sg), ptl, 0, 2, 1, 1);

    app.p2p_send_subs_entry = gtk_entry_new();
    gtk_entry_set_text(
        GTK_ENTRY(app.p2p_send_subs_entry), "16");
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.p2p_send_subs_entry),
        "16");
    gtk_widget_set_hexpand(
        app.p2p_send_subs_entry, FALSE);
    gtk_entry_set_width_chars(
        GTK_ENTRY(app.p2p_send_subs_entry), 4);
    gtk_grid_attach(GTK_GRID(sg),
        app.p2p_send_subs_entry, 1, 2, 1, 1);

    gtk_box_pack_start(GTK_BOX(page),
        sg, FALSE, FALSE, 0);

    /* Send buttons */
    GtkWidget *send_btn_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);

    app.p2p_start_btn = mkbtn(
        "Start P2P Server",
        "act-btn");
    g_signal_connect(app.p2p_start_btn, "clicked",
        G_CALLBACK(on_p2p_start), NULL);

    app.p2p_stop_btn = mkbtn("Stop", "stop-btn");
    gtk_widget_set_sensitive(app.p2p_stop_btn, FALSE);
    g_signal_connect(app.p2p_stop_btn, "clicked",
        G_CALLBACK(on_p2p_stop), NULL);

    gtk_box_pack_start(GTK_BOX(send_btn_bar),
        app.p2p_start_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(send_btn_bar),
        app.p2p_stop_btn, FALSE, FALSE, 0);

    /* Status label */
    app.p2p_send_status_label =
        gtk_label_new("Not running");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(
            app.p2p_send_status_label),
        "addr-lbl");
    gtk_widget_set_halign(
        app.p2p_send_status_label,
        GTK_ALIGN_START);
    gtk_label_set_selectable(
        GTK_LABEL(app.p2p_send_status_label), TRUE);
    gtk_box_pack_start(GTK_BOX(send_btn_bar),
        app.p2p_send_status_label, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(page),
        send_btn_bar, FALSE, FALSE, 4);

    /* ── Separator ───────────────────────────── */
    gtk_box_pack_start(GTK_BOX(page),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
        FALSE, FALSE, 6);

    /* ── Receive Section ─────────────────────── */
    GtkWidget *recv_hdr = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(recv_hdr),
        "<b>Receive a File</b>");
    gtk_widget_set_halign(recv_hdr, GTK_ALIGN_START);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(recv_hdr), "sec-title");
    gtk_box_pack_start(GTK_BOX(page),
        recv_hdr, FALSE, FALSE, 4);

    /* Receive grid */
    GtkWidget *rg = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(rg), 8);
    gtk_grid_set_column_spacing(GTK_GRID(rg), 10);

    /* Address */
    GtkWidget *al = gtk_label_new("Address:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(al), "dim-text");
    gtk_widget_set_halign(al, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(rg), al, 0, 0, 1, 1);

    app.p2p_recv_addr_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.p2p_recv_addr_entry),
        "IP:port (e.g. 192.168.1.5:9900)");
    gtk_widget_set_hexpand(
        app.p2p_recv_addr_entry, TRUE);
    gtk_grid_attach(GTK_GRID(rg),
        app.p2p_recv_addr_entry, 1, 0, 1, 1);

    /* Password */
    GtkWidget *rl = gtk_label_new("Password:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(rl), "dim-text");
    gtk_widget_set_halign(rl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(rg), rl, 0, 1, 1, 1);

    app.p2p_recv_password_entry = gtk_entry_new();
    gtk_entry_set_visibility(
        GTK_ENTRY(app.p2p_recv_password_entry),
        FALSE);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.p2p_recv_password_entry),
        "Password from sender");
    gtk_entry_set_input_purpose(
        GTK_ENTRY(app.p2p_recv_password_entry),
        GTK_INPUT_PURPOSE_PASSWORD);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(
            app.p2p_recv_password_entry),
        "pwd-entry");
    gtk_widget_set_hexpand(
        app.p2p_recv_password_entry, TRUE);
    gtk_grid_attach(GTK_GRID(rg),
        app.p2p_recv_password_entry, 1, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(page),
        rg, FALSE, FALSE, 0);

    /* Receive button */
    app.p2p_recv_btn = mkbtn(
        "Receive & Decrypt",
        "act-btn");
    g_signal_connect(app.p2p_recv_btn, "clicked",
        G_CALLBACK(on_p2p_recv), NULL);
    gtk_widget_set_halign(
        app.p2p_recv_btn, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page),
        app.p2p_recv_btn, FALSE, FALSE, 4);

    /* ── Progress + Log ──────────────────────── */
    app.p2p_progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(page),
        app.p2p_progress, FALSE, FALSE, 0);

    GtkWidget *log_scroll =
        gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC,
        GTK_POLICY_AUTOMATIC);

    app.p2p_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.p2p_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.p2p_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.p2p_log_view),
        GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.p2p_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(
            app.p2p_log_view),
        "log-area");

    app.p2p_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.p2p_log_view));
    gtk_container_add(
        GTK_CONTAINER(log_scroll),
        app.p2p_log_view);
    gtk_widget_set_vexpand(log_scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page),
        log_scroll, TRUE, TRUE, 0);

    return page;
}
