#include "gui.h"
#include "gui_css.h"
#include "gui_page_share.h"
#include "gui_page_recv.h"
#include "gui_page_send.h"
#include "gui_page_vault.h"
#include "gui_page_server.h"
#include "server.h"

/* ── Mode switching ────────────────────────────────────────── */

void gui_switch_mode(int mode)
{
    app.current_mode = mode;

    const char *pages[] = {
        "share", "recv", "send", "vault", "server"
    };
    const char *active_cls = "mode-active";
    const char *normal_cls = "mode-btn";

    for (int i = 0; i < 5; i++) {
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

static void on_quit(GtkWidget *w, gpointer u)
{
    (void)w; (void)u;
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
        GTK_WINDOW(app.window), 900, 720);
    g_signal_connect(app.window, "destroy",
                     G_CALLBACK(on_quit), NULL);

    /* Header bar */
    app.header_bar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(
        GTK_HEADER_BAR(app.header_bar), TRUE);
    gtk_header_bar_set_title(
        GTK_HEADER_BAR(app.header_bar),
        "SecureDrop");
    gtk_header_bar_set_subtitle(
        GTK_HEADER_BAR(app.header_bar),
        "v" APP_VERSION " | AES-256-GCM | RSA-2048 | "
        "Distributed Storage");
    gtk_window_set_titlebar(
        GTK_WINDOW(app.window), app.header_bar);

    /* Main vertical box */
    GtkWidget *main_box = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), main_box);

    /* Mode navigation bar */
    GtkWidget *nav_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 3);
    gtk_widget_set_halign(nav_bar, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(nav_bar, 10);
    gtk_widget_set_margin_bottom(nav_bar, 4);

    const char *labels[] = {
        "Share", "Receive", "Send", "Vault", "Server"
    };
    void (*callbacks[])(GtkButton *, gpointer) = {
        on_mode0, on_mode1, on_mode2, on_mode3, on_mode4
    };

    for (int i = 0; i < 5; i++) {
        app.mode_btns[i] = gtk_button_new_with_label(labels[i]);
        gtk_style_context_add_class(
            gtk_widget_get_style_context(app.mode_btns[i]),
            i == 0 ? "mode-active" : "mode-btn");
        g_signal_connect(app.mode_btns[i], "clicked",
                         G_CALLBACK(callbacks[i]), NULL);
        gtk_box_pack_start(GTK_BOX(nav_bar),
                           app.mode_btns[i], FALSE, FALSE, 0);
    }

    gtk_box_pack_start(GTK_BOX(main_box),
                       nav_bar, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
        FALSE, FALSE, 0);

    /* Page stack */
    app.main_stack = gtk_stack_new();
    gtk_stack_set_transition_type(
        GTK_STACK(app.main_stack),
        GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
    gtk_stack_set_transition_duration(
        GTK_STACK(app.main_stack), 150);

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

    gtk_box_pack_start(GTK_BOX(main_box),
                       app.main_stack, TRUE, TRUE, 0);

    /* Footer */
    GtkWidget *footer = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(footer),
        "<span size=\"small\" color=\"#404060\">"
        "HKDF-SHA256 | PBKDF2 | Multi-Tor | "
        "Distributed Chunks | Secure Vault"
        "</span>");
    gtk_widget_set_margin_start(footer, 14);
    gtk_widget_set_margin_bottom(footer, 6);
    gtk_widget_set_margin_top(footer, 3);
    gtk_widget_set_halign(footer, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(main_box),
                       footer, FALSE, FALSE, 0);

    /* Show all, then hide dynamic elements */
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.share_status_box);
    gtk_widget_hide(app.share_file_scroll);
}