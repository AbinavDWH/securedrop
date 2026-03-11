#include "gui_page_send.h"
#include "gui_helpers.h"
#include "client.h"
#include "tor.h"
#include "crypto.h"
#include "util.h"

static GtkWidget *mkbtn(const char *label, const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* ── Callbacks ─────────────────────────────────────────────── */

static void on_send(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    char *filepath = gtk_file_chooser_get_filename(
        GTK_FILE_CHOOSER(app.send_file_btn));
    if (!filepath || !*filepath) {
        gui_post_log(LOG_SEND, "Select a file first");
        g_free(filepath);
        return;
    }

    const char *addr = gtk_entry_get_text(
        GTK_ENTRY(app.send_addr_entry));
    if (!addr || !*addr) {
        gui_post_log(LOG_SEND, "Enter server address");
        g_free(filepath);
        return;
    }

    const char *password = gtk_entry_get_text(
        GTK_ENTRY(app.send_password_entry));
    if (!password || strlen(password) < 4) {
        gui_post_log(LOG_SEND,
            "Password must be at least 4 characters");
        g_free(filepath);
        return;
    }

    gui_post_log(LOG_SEND, "Starting encrypted upload...");
    gui_post_progress(LOG_SEND, 0.0);

    client_upload_file(filepath, addr, password);
    g_free(filepath);
}

static void on_scan_circuits(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    tor_init_circuits();
    tor_log_status(LOG_SEND);

    int n = tor_active_count();
    char lbl[128];
    snprintf(lbl, sizeof(lbl), "%d circuit(s) active", n);
    gtk_label_set_text(
        GTK_LABEL(app.send_circuit_label), lbl);
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_send_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(page), 14);

    /* Header */
    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(hdr),
        gtk_image_new_from_icon_name(
            "mail-send", GTK_ICON_SIZE_DND),
        FALSE, FALSE, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<b>Send File</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title), "sec-title");
    gtk_box_pack_start(GTK_BOX(hdr), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), hdr, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new(
        "Encrypt locally and upload to server via Tor. "
        "Set a password for the receiver.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub), "dim-text");
    gtk_widget_set_halign(sub, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), sub, FALSE, FALSE, 0);

    /* Tor circuit bar */
    GtkWidget *tor_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *scan_btn = mkbtn("Scan Tor Circuits", "sec-btn");
    g_signal_connect(scan_btn, "clicked",
                     G_CALLBACK(on_scan_circuits), NULL);
    gtk_box_pack_start(GTK_BOX(tor_bar),
                       scan_btn, FALSE, FALSE, 0);

    app.send_circuit_label = gtk_label_new("Not scanned");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.send_circuit_label),
        "circuit-label");
    gtk_box_pack_start(GTK_BOX(tor_bar),
                       app.send_circuit_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page),
                       tor_bar, FALSE, FALSE, 0);

    /* Input grid */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    /* File chooser */
    GtkWidget *fl = gtk_label_new("File:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(fl), "dim-text");
    gtk_widget_set_halign(fl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), fl, 0, 0, 1, 1);

    app.send_file_btn = gtk_file_chooser_button_new(
        "Select File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_widget_set_hexpand(app.send_file_btn, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.send_file_btn, 1, 0, 1, 1);

    /* Server address */
    GtkWidget *al = gtk_label_new("Server:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(al), "dim-text");
    gtk_widget_set_halign(al, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), al, 0, 1, 1, 1);

    app.send_addr_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.send_addr_entry),
        "address:port or .onion:port");
    gtk_widget_set_hexpand(app.send_addr_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.send_addr_entry, 1, 1, 1, 1);

    /* Password */
    GtkWidget *pl = gtk_label_new("Password:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(pl), "dim-text");
    gtk_widget_set_halign(pl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid), pl, 0, 2, 1, 1);

    app.send_password_entry = gtk_entry_new();
    gtk_entry_set_visibility(
        GTK_ENTRY(app.send_password_entry), FALSE);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.send_password_entry),
        "Password to protect this file");
    gtk_entry_set_input_purpose(
        GTK_ENTRY(app.send_password_entry),
        GTK_INPUT_PURPOSE_PASSWORD);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.send_password_entry),
        "pwd-entry");
    gtk_widget_set_hexpand(app.send_password_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid),
                    app.send_password_entry, 1, 2, 1, 1);

    gtk_box_pack_start(GTK_BOX(page), grid, FALSE, FALSE, 0);

    /* Send button */
    app.send_btn = mkbtn(
        "\xF0\x9F\x94\x92  Encrypt & Upload", "act-btn");
    g_signal_connect(app.send_btn, "clicked",
                     G_CALLBACK(on_send), NULL);
    gtk_widget_set_halign(app.send_btn, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page),
                       app.send_btn, FALSE, FALSE, 0);

    /* File ID display */
    GtkWidget *id_box = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *id_lbl = gtk_label_new("File ID:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(id_lbl), "dim-text");
    gtk_box_pack_start(GTK_BOX(id_box),
                       id_lbl, FALSE, FALSE, 0);

    app.send_fileid_label = gtk_label_new("—");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.send_fileid_label),
        "fileid-lbl");
    gtk_label_set_selectable(
        GTK_LABEL(app.send_fileid_label), TRUE);
    gtk_box_pack_start(GTK_BOX(id_box),
                       app.send_fileid_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(page),
                       id_box, FALSE, FALSE, 0);

    /* Progress */
    app.send_progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(page),
                       app.send_progress, FALSE, FALSE, 0);

    /* Log */
    GtkWidget *log_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    app.send_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.send_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.send_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.send_log_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.send_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.send_log_view),
        "log-area");

    app.send_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.send_log_view));
    gtk_container_add(GTK_CONTAINER(log_scroll),
                      app.send_log_view);
    gtk_widget_set_vexpand(log_scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page),
                       log_scroll, TRUE, TRUE, 0);

    return page;
}