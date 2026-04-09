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

#include "gui.h"
#include "gui_css.h"
#include "gui_page_share.h"
#include "gui_page_recv.h"
#include "gui_page_send.h"
#include "gui_page_vault.h"
#include "gui_page_server.h"
#include "gui_page_p2p.h"
#include "gui_page_advanced.h"
#include "server.h"
#include "p2p.h"

/* ── Mode switching ────────────────────────────────────────── */

void gui_switch_mode(int mode)
{
    app.current_mode = mode;

    const char *pages[] = {
        "share", "recv", "send", "vault",
        "server", "p2p", "advanced"
    };
    const char *active_cls = "sidebar-nav-active";
    const char *normal_cls = "sidebar-nav-btn";

    for (int i = 0; i < 7; i++) {
        GtkStyleContext *sc =
            gtk_widget_get_style_context(app.mode_btns[i]);
        gtk_style_context_remove_class(sc, active_cls);
        gtk_style_context_remove_class(sc, normal_cls);
        gtk_style_context_add_class(sc,
            i == mode ? active_cls : normal_cls);
    }

    gtk_stack_set_visible_child_name(
        GTK_STACK(app.main_stack), pages[mode]);
}

/* ── Mode button callbacks ─────────────────────────────────── */

static void on_mode0(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(0);
}
static void on_mode1(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(1);
}
static void on_mode2(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(2);
}
static void on_mode3(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(3);
}
static void on_mode4(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(4);
}
static void on_mode5(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(5);
}
static void on_mode6(GtkButton *b, gpointer u)
{
    (void)b; (void)u; gui_switch_mode(6);
}

static void on_quit(GtkWidget *w, gpointer u)
{
    (void)w; (void)u;
    if (p2p_is_running())
        p2p_stop_sender(LOG_P2P);
    server_stop(LOG_SHARE);
    gtk_main_quit();
}

/* ── Build main window ─────────────────────────────────────── */

void gui_build(void)
{
    /* Load CSS theme */
    app.css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(
        app.css, gui_get_css_theme(), -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(app.css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    /* Main window */
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(
        GTK_WINDOW(app.window), 1000, 720);
    g_signal_connect(app.window, "destroy",
                     G_CALLBACK(on_quit), NULL);

    /* Minimal header bar */
    app.header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(
        GTK_HEADER_BAR(app.header_bar), TRUE);
    gtk_header_bar_set_decoration_layout(
        GTK_HEADER_BAR(app.header_bar), ":minimize,maximize,close");
    gtk_header_bar_set_title(
        GTK_HEADER_BAR(app.header_bar), NULL);
    gtk_header_bar_set_subtitle(
        GTK_HEADER_BAR(app.header_bar), NULL);
    gtk_widget_set_size_request(app.header_bar, -1, 1);
    gtk_window_set_titlebar(
        GTK_WINDOW(app.window), app.header_bar);

    /* ── Root horizontal box: sidebar | content ──────────── */
    GtkWidget *root_box = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), root_box);

    /* ── Sidebar ─────────────────────────────────────────── */
    app.sidebar = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(app.sidebar, 220, -1);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.sidebar), "sidebar");

    /* Brand area */
    GtkWidget *brand_box = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(brand_box), "sidebar-brand");

    GtkWidget *brand_icon = gtk_image_new_from_icon_name(
        "security-high-symbolic", GTK_ICON_SIZE_MENU);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(brand_icon),
        "sidebar-brand-icon");
    gtk_box_pack_start(GTK_BOX(brand_box),
        brand_icon, FALSE, FALSE, 0);

    GtkWidget *brand_title = gtk_label_new("Veil-Xfer");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(brand_title),
        "sidebar-brand-title");
    gtk_box_pack_start(GTK_BOX(brand_box),
        brand_title, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(app.sidebar),
        brand_box, FALSE, FALSE, 0);

    /* Version info */
    GtkWidget *ver_label = gtk_label_new(
        "v" APP_VERSION " | AES 256 GCM\n"
        "RSA-4096 | Distributed Storage");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(ver_label), "sidebar-info");
    gtk_widget_set_halign(ver_label, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(ver_label), TRUE);
    gtk_box_pack_start(GTK_BOX(app.sidebar),
        ver_label, FALSE, FALSE, 0);

    /* Separator between brand and nav */
    gtk_box_pack_start(GTK_BOX(app.sidebar),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
        FALSE, FALSE, 2);

    /* Navigation buttons with GTK symbolic icons */
    const char *nav_icons[] = {
        "send-to-symbolic",
        "document-save-symbolic",
        "go-up-symbolic",
        "channel-secure-symbolic",
        "network-server-symbolic",
        "system-users-symbolic",
        "preferences-system-symbolic"
    };
    const char *nav_labels[] = {
        "Share", "Receive", "Send",
        "Vault", "Server", "P2P", "Advanced"
    };
    void (*callbacks[])(GtkButton *, gpointer) = {
        on_mode0, on_mode1, on_mode2, on_mode3,
        on_mode4, on_mode5, on_mode6
    };

    for (int i = 0; i < 7; i++) {
        app.mode_btns[i] = gtk_button_new();

        GtkWidget *btn_box = gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *icon = gtk_image_new_from_icon_name(
            nav_icons[i], GTK_ICON_SIZE_MENU);
        GtkWidget *lbl = gtk_label_new(nav_labels[i]);
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);

        gtk_box_pack_start(GTK_BOX(btn_box),
            icon, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(btn_box),
            lbl, TRUE, TRUE, 0);
        gtk_container_add(GTK_CONTAINER(app.mode_btns[i]),
                          btn_box);

        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.mode_btns[i]),
            i == 0 ? "sidebar-nav-active" : "sidebar-nav-btn");
        g_signal_connect(app.mode_btns[i], "clicked",
                         G_CALLBACK(callbacks[i]), NULL);
        gtk_box_pack_start(GTK_BOX(app.sidebar),
                           app.mode_btns[i], FALSE, FALSE, 3);
    }

    /* Spacer to push footer down */
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_pack_start(GTK_BOX(app.sidebar),
        spacer, TRUE, TRUE, 0);

    /* Footer in sidebar */
    GtkWidget *footer = gtk_label_new(
        "HKDF-SHA256 | PBKDF2\n"
        "Multi-Tor | Secure Vault");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(footer), "sidebar-footer");
    gtk_widget_set_halign(footer, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(footer), TRUE);
    gtk_box_pack_start(GTK_BOX(app.sidebar),
        footer, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root_box),
        app.sidebar, FALSE, FALSE, 0);

    /* ── Content area (wrapped in card) ──────────────────── */
    GtkWidget *content_wrap = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(content_wrap),
        "content-wrapper");
    gtk_widget_set_hexpand(content_wrap, TRUE);
    gtk_widget_set_vexpand(content_wrap, TRUE);

    app.main_stack = gtk_stack_new();
    gtk_stack_set_transition_type(
        GTK_STACK(app.main_stack),
        GTK_STACK_TRANSITION_TYPE_SLIDE_UP_DOWN);
    gtk_stack_set_transition_duration(
        GTK_STACK(app.main_stack), 200);
    gtk_widget_set_hexpand(app.main_stack, TRUE);
    gtk_widget_set_vexpand(app.main_stack, TRUE);

    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_share_page(), "share");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_recv_page(), "recv");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_send_page(), "send");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_vault_page(), "vault");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_server_page(), "server");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_p2p_page(), "p2p");
    gtk_stack_add_named(GTK_STACK(app.main_stack),
        gui_build_advanced_page(), "advanced");

    gtk_box_pack_start(GTK_BOX(content_wrap),
                       app.main_stack, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(root_box),
                       content_wrap, TRUE, TRUE, 0);

    /* Show all, then hide dynamic elements */
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.share_status_box);
    gtk_widget_hide(app.share_file_scroll);
}