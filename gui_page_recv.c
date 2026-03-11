#include "gui_page_recv.h"
#include "gui_helpers.h"
#include "client.h"
#include "tor.h"
#include "util.h"

static GtkWidget *mkbtn(const char *label, const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* ── Fetch callback ────────────────────────────────────────── */

static void on_fetch(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    const char *server = gtk_entry_get_text(
        GTK_ENTRY(app.recv_server_entry));
    const char *file_id = gtk_entry_get_text(
        GTK_ENTRY(app.recv_fileid_entry));
    const char *password = gtk_entry_get_text(
        GTK_ENTRY(app.recv_password_entry));

    if (!server || !*server) {
        gui_post_log(LOG_RECV, "Enter server address");
        return;
    }
    if (!file_id || strlen(file_id) < 16) {
        gui_post_log(LOG_RECV,
            "Enter valid file ID (64 hex characters)");
        return;
    }
    if (!password || !*password) {
        gui_post_log(LOG_RECV, "Enter password");
        return;
    }

    /* Warn if .onion but no Tor detected */
    if (strstr(server, ".onion") != NULL) {
        int tc = tor_active_count();
        if (tc == 0) {
            gui_post_log(LOG_RECV,
                "WARNING: .onion address detected but "
                "no Tor SOCKS5 found");
            gui_post_log(LOG_RECV,
                "Will attempt to find Tor on "
                "standard ports...");
        }
    }

    gui_post_log(LOG_RECV, "Starting download...");
    gui_post_progress(LOG_RECV, 0.0);

    client_download_file(server, file_id, password);
}

static void on_scan_tor(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    gui_post_log(LOG_RECV, "Scanning for Tor...");
    tor_init_circuits();
    tor_log_status(LOG_RECV);

    int n = tor_active_count();
    if (n == 0) {
        gui_post_log(LOG_RECV, "");
        gui_post_log(LOG_RECV,
            "To use .onion addresses, install Tor:");
        gui_post_log(LOG_RECV,
            "  sudo apt install tor");
        gui_post_log(LOG_RECV,
            "  sudo systemctl start tor");
        gui_post_log(LOG_RECV,
            "  sudo systemctl enable tor");
        gui_post_log(LOG_RECV,
            "Then click 'Scan Tor' again.");
    }
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_recv_page(void)
{
    GtkWidget *page = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(page), 14);

    /* Header */
    GtkWidget *hdr = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(hdr),
        gtk_image_new_from_icon_name(
            "folder-download", GTK_ICON_SIZE_DND),
        FALSE, FALSE, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<b>Receive Files</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title), "sec-title");
    gtk_box_pack_start(GTK_BOX(hdr), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), hdr, FALSE, FALSE, 0);

    GtkWidget *sub_lbl = gtk_label_new(
        "Download encrypted files using "
        "File ID + Password. "
        "Supports .onion addresses via Tor.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub_lbl), "dim-text");
    gtk_widget_set_halign(sub_lbl, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(sub_lbl), TRUE);
    gtk_box_pack_start(GTK_BOX(page),
                       sub_lbl, FALSE, FALSE, 0);

    /* Tor status bar */
    GtkWidget *tor_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(tor_bar), "status-box");

    GtkWidget *tor_icon = gtk_label_new(
        "\xF0\x9F\x8C\x8D");  /* 🌍 */
    gtk_box_pack_start(GTK_BOX(tor_bar),
                       tor_icon, FALSE, FALSE, 0);

    GtkWidget *tor_lbl = gtk_label_new(NULL);
    int tc = tor_active_count();
    if (tc > 0) {
        char tbuf[128];
        snprintf(tbuf, sizeof(tbuf),
            "<span color='#66bb6a'>%d Tor circuit(s) "
            "ready</span>", tc);
        gtk_label_set_markup(GTK_LABEL(tor_lbl), tbuf);
    } else {
        gtk_label_set_markup(GTK_LABEL(tor_lbl),
            "<span color='#ffa726'>No Tor detected — "
            "click Scan</span>");
    }
    gtk_box_pack_start(GTK_BOX(tor_bar),
                       tor_lbl, TRUE, TRUE, 0);

    GtkWidget *scan_btn = mkbtn("Scan Tor", "sec-btn");
    g_signal_connect(scan_btn, "clicked",
                     G_CALLBACK(on_scan_tor), NULL);
    gtk_box_pack_end(GTK_BOX(tor_bar),
                     scan_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page),
                       tor_bar, FALSE, FALSE, 0);

    /* Input grid */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    /* Server address */
    GtkWidget *lbl1 = gtk_label_new("Server:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(lbl1), "dim-text");
    gtk_widget_set_halign(lbl1, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl1, 0, 0, 1, 1);

    app.recv_server_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.recv_server_entry),
        "IP:port or xxxxx.onion:80");
    gtk_widget_set_hexpand(app.recv_server_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.recv_server_entry, 1, 0, 1, 1);

    /* File ID */
    GtkWidget *lbl2 = gtk_label_new("File ID:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(lbl2), "dim-text");
    gtk_widget_set_halign(lbl2, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl2, 0, 1, 1, 1);

    app.recv_fileid_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.recv_fileid_entry),
        "64-char hex ID from sender");
    gtk_widget_set_hexpand(app.recv_fileid_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.recv_fileid_entry, 1, 1, 1, 1);

    /* Password */
    GtkWidget *lbl3 = gtk_label_new("Password:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(lbl3), "dim-text");
    gtk_widget_set_halign(lbl3, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), lbl3, 0, 2, 1, 1);

    app.recv_password_entry = gtk_entry_new();
    gtk_entry_set_visibility(
        GTK_ENTRY(app.recv_password_entry), FALSE);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.recv_password_entry),
        "Password from sender");
    gtk_entry_set_input_purpose(
        GTK_ENTRY(app.recv_password_entry),
        GTK_INPUT_PURPOSE_PASSWORD);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.recv_password_entry),
        "pwd-entry");
    gtk_widget_set_hexpand(app.recv_password_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.recv_password_entry, 1, 2, 1, 1);

    gtk_box_pack_start(GTK_BOX(page), grid, FALSE, FALSE, 0);

    /* Fetch button */
    app.recv_fetch_btn = mkbtn(
        "\xF0\x9F\x94\x93  Download & Decrypt", "act-btn");
    g_signal_connect(app.recv_fetch_btn, "clicked",
                     G_CALLBACK(on_fetch), NULL);
    gtk_widget_set_halign(app.recv_fetch_btn, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page),
                       app.recv_fetch_btn, FALSE, FALSE, 0);

    /* Progress */
    app.recv_progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(page),
                       app.recv_progress, FALSE, FALSE, 0);

    /* Log */
    GtkWidget *log_scroll = gtk_scrolled_window_new(
        NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    app.recv_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.recv_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.recv_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.recv_log_view),
        GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.recv_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.recv_log_view),
        "log-area");

    app.recv_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.recv_log_view));
    gtk_container_add(GTK_CONTAINER(log_scroll),
                      app.recv_log_view);
    gtk_widget_set_vexpand(log_scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page),
                       log_scroll, TRUE, TRUE, 0);

    return page;
}