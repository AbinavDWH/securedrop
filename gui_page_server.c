#include "gui_page_server.h"
#include "gui_helpers.h"
#include "server.h"
#include "storage.h"
#include "util.h"
#include "onion.h"

static GtkWidget *mkbtn(const char *label, const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

static void on_copy_onion(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    const char *addr = onion_get_full_address();
    if (addr) {
        gtk_clipboard_set_text(
            gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
            addr, -1);
        gui_post_log(LOG_SERVER, "Onion address copied");
    } else {
        gui_post_log(LOG_SERVER, "No onion address yet");
    }
}

/* ── Update stats display ──────────────────────────────────── */

static void update_stats(void)
{
    if (!app.server_stats_label) return;

    int active = storage_active_subserver_count();

    pthread_mutex_lock(&app.subserver_mutex);
    int total = app.num_sub_servers;
    int min_port = 0, max_port = 0;
    if (total > 0) {
        min_port = app.sub_servers[0].port;
        max_port = app.sub_servers[total - 1].port;
    }
    pthread_mutex_unlock(&app.subserver_mutex);

    char stats[512];
    if (total > 0) {
        snprintf(stats, sizeof(stats),
            "Sub-servers: %d/%d active | "
            "Ports: %d–%d | "
            "Files: %d | "
            "Up: %d | Down: %d",
            active, total,
            min_port, max_port,
            app.stored_file_count,
            app.upload_count,
            app.download_count);
    } else {
        snprintf(stats, sizeof(stats),
            "Sub-servers: 0 | "
            "Files: %d | "
            "Up: %d | Down: %d",
            app.stored_file_count,
            app.upload_count,
            app.download_count);
    }

    gtk_label_set_text(
        GTK_LABEL(app.server_stats_label), stats);
}

static void refresh_stored_files(void)
{
    if (!app.server_files_store) return;
    gtk_list_store_clear(app.server_files_store);

    pthread_mutex_lock(&app.stored_mutex);
    for (int i = 0; i < app.stored_file_count; i++) {
        StoredFileMeta *m = &app.stored_files[i];
        char sz[64], id_s[20], ch[32], ts[64];
        human_size(m->original_size, sz, sizeof(sz));
        snprintf(id_s, sizeof(id_s), "%.16s...", m->file_id);
        snprintf(ch, sizeof(ch), "%u chunks", m->chunk_count);
        struct tm *tm = localtime(&m->upload_time);
        if (tm) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", tm);
        else strcpy(ts, "unknown");

        GtkTreeIter it;
        gtk_list_store_append(app.server_files_store, &it);
        gtk_list_store_set(app.server_files_store, &it,
            COL_ICON, "document-save-symbolic",
            COL_NAME, m->original_name,
            COL_SIZE, sz, COL_PATH, ch,
            COL_STATUS, ts, COL_ID, id_s, -1);
    }
    pthread_mutex_unlock(&app.stored_mutex);
}

/* ── Callbacks ─────────────────────────────────────────────── */

static void on_start(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    server_start(LOG_SERVER);
    gtk_widget_set_sensitive(app.server_start_btn, FALSE);
    gtk_widget_set_sensitive(app.server_stop_btn, TRUE);

    if (app.server_onion_status)
        gtk_label_set_markup(
            GTK_LABEL(app.server_onion_status),
            "<span color='#ffa726'>Starting...</span>");
    if (app.server_onion_label)
        gtk_label_set_text(
            GTK_LABEL(app.server_onion_label),
            "Waiting for Tor...");

    refresh_stored_files();
    update_stats();
}

static void on_stop(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    server_stop(LOG_SERVER);
    gtk_widget_set_sensitive(app.server_start_btn, TRUE);
    gtk_widget_set_sensitive(app.server_stop_btn, FALSE);

    if (app.server_onion_status)
        gtk_label_set_markup(
            GTK_LABEL(app.server_onion_status),
            "<span color='#707090'>Offline</span>");
    if (app.server_onion_label)
        gtk_label_set_text(
            GTK_LABEL(app.server_onion_label),
            "Not running");

    update_stats();
}

static void on_refresh(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    refresh_stored_files();
    update_stats();
    gui_post_log(LOG_SERVER,
        "Refreshed (%d files, %d sub-servers)",
        app.stored_file_count,
        storage_active_subserver_count());
}

/* ── Add single sub-server ─────────────────────────────────── */

static void on_add_sub(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    const char *text = gtk_entry_get_text(
        GTK_ENTRY(app.server_subserver_entry));
    if (!text || !*text) {
        gui_post_log(LOG_SERVER,
            "Enter port (%d–%d)",
            SUB_PORT_BASE, SUB_PORT_MAX);
        return;
    }

    int port = atoi(text);
    if (port < SUB_PORT_BASE || port > SUB_PORT_MAX) {
        gui_post_log(LOG_SERVER,
            "Port %d out of range [%d–%d]",
            port, SUB_PORT_BASE, SUB_PORT_MAX);
        return;
    }

    int idx = storage_add_subserver("127.0.0.1", port,
                                    LOG_SERVER);
    if (idx >= 0)
        storage_start_subserver(idx, LOG_SERVER);

    gtk_entry_set_text(
        GTK_ENTRY(app.server_subserver_entry), "");
    update_stats();
}

/* ── Batch add sub-servers ─────────────────────────────────── */

static void on_batch_add(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    const char *text = gtk_entry_get_text(
        GTK_ENTRY(app.server_batch_entry));
    if (!text || !*text) {
        gui_post_log(LOG_SERVER,
            "Enter number of sub-servers (1–%d)",
            MAX_SUB_SERVERS);
        return;
    }

    int count = atoi(text);
    if (count <= 0) {
        gui_post_log(LOG_SERVER, "Enter a positive number");
        return;
    }

    int remaining = MAX_SUB_SERVERS - app.num_sub_servers;
    int port_remaining = SUB_PORT_MAX - SUB_PORT_BASE + 1
                         - app.num_sub_servers;

    if (count > remaining) count = remaining;
    if (count > port_remaining) count = port_remaining;

    if (count <= 0) {
        gui_post_log(LOG_SERVER,
            "No more ports available "
            "(max %d, range %d–%d)",
            MAX_SUB_SERVERS,
            SUB_PORT_BASE, SUB_PORT_MAX);
        return;
    }

    gui_post_log(LOG_SERVER,
        "Starting batch: %d sub-servers...", count);

    int added = storage_add_subservers_batch(
        count, LOG_SERVER);

    gui_post_log(LOG_SERVER,
        "Batch result: %d/%d sub-servers started",
        added, count);

    gtk_entry_set_text(
        GTK_ENTRY(app.server_batch_entry), "");
    update_stats();
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_server_page(void)
{
    GtkWidget *page = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(page), 14);

    /* 1. Header */
    GtkWidget *hdr = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(hdr),
        gtk_image_new_from_icon_name(
            "network-server", GTK_ICON_SIZE_DND),
        FALSE, FALSE, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<b>Distributed Storage Server</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title), "sec-title");
    gtk_box_pack_start(GTK_BOX(hdr), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), hdr, FALSE, FALSE, 0);

    char desc_text[256];
    snprintf(desc_text, sizeof(desc_text),
        "Main server (port %d) with up to %d "
        "sub-servers (ports %d–%d)",
        SERVER_PORT, MAX_SUB_SERVERS,
        SUB_PORT_BASE, SUB_PORT_MAX);
    GtkWidget *desc = gtk_label_new(desc_text);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(desc), "dim-text");
    gtk_widget_set_halign(desc, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), desc, FALSE, FALSE, 0);

    /* 2. Control buttons */
    GtkWidget *btn_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    app.server_start_btn = mkbtn("Start Server", "act-btn");
    app.server_stop_btn = mkbtn("Stop", "stop-btn");
    GtkWidget *ref_btn = mkbtn("Refresh", "sec-btn");
    gtk_widget_set_sensitive(app.server_stop_btn, FALSE);

    g_signal_connect(app.server_start_btn, "clicked",
                     G_CALLBACK(on_start), NULL);
    g_signal_connect(app.server_stop_btn, "clicked",
                     G_CALLBACK(on_stop), NULL);
    g_signal_connect(ref_btn, "clicked",
                     G_CALLBACK(on_refresh), NULL);

    gtk_box_pack_start(GTK_BOX(btn_bar),
        app.server_start_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
        app.server_stop_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
        ref_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page),
        btn_bar, FALSE, FALSE, 0);

    /* 3. Sub-server management */
    GtkWidget *sub_frame = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub_frame), "status-box");

    GtkWidget *sub_title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sub_title),
        "<b>Sub-Server Management</b>");
    gtk_widget_set_halign(sub_title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(sub_frame),
        sub_title, FALSE, FALSE, 0);

    char range_text[256];
    snprintf(range_text, sizeof(range_text),
        "Distribute chunks across sub-servers. "
        "Port range: %d–%d (max %d servers)",
        SUB_PORT_BASE, SUB_PORT_MAX, MAX_SUB_SERVERS);
    GtkWidget *sub_desc = gtk_label_new(range_text);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub_desc), "dim-text");
    gtk_widget_set_halign(sub_desc, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(sub_desc), TRUE);
    gtk_box_pack_start(GTK_BOX(sub_frame),
        sub_desc, FALSE, FALSE, 0);

    /* Single add row */
    GtkWidget *single_row = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);

    GtkWidget *port_lbl = gtk_label_new("Port:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(port_lbl), "dim-text");
    gtk_box_pack_start(GTK_BOX(single_row),
        port_lbl, FALSE, FALSE, 0);

    app.server_subserver_entry = gtk_entry_new();
    char ph[64];
    snprintf(ph, sizeof(ph), "%d–%d",
             SUB_PORT_BASE, SUB_PORT_MAX);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.server_subserver_entry), ph);
    gtk_entry_set_width_chars(
        GTK_ENTRY(app.server_subserver_entry), 8);
    gtk_box_pack_start(GTK_BOX(single_row),
        app.server_subserver_entry, FALSE, FALSE, 0);

    app.server_add_sub_btn = mkbtn("Add", "sec-btn");
    g_signal_connect(app.server_add_sub_btn, "clicked",
                     G_CALLBACK(on_add_sub), NULL);
    gtk_box_pack_start(GTK_BOX(single_row),
        app.server_add_sub_btn, FALSE, FALSE, 0);

    /* Separator */
    gtk_box_pack_start(GTK_BOX(single_row),
        gtk_separator_new(GTK_ORIENTATION_VERTICAL),
        FALSE, FALSE, 4);

    /* Batch add */
    GtkWidget *batch_lbl = gtk_label_new("Batch:");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(batch_lbl), "dim-text");
    gtk_box_pack_start(GTK_BOX(single_row),
        batch_lbl, FALSE, FALSE, 0);

    app.server_batch_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(app.server_batch_entry), "e.g., 10");
    gtk_entry_set_width_chars(
        GTK_ENTRY(app.server_batch_entry), 6);
    gtk_box_pack_start(GTK_BOX(single_row),
        app.server_batch_entry, FALSE, FALSE, 0);

    app.server_batch_btn = mkbtn(
        "Add Multiple", "warn-btn");
    g_signal_connect(app.server_batch_btn, "clicked",
                     G_CALLBACK(on_batch_add), NULL);
    gtk_box_pack_start(GTK_BOX(single_row),
        app.server_batch_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(sub_frame),
        single_row, FALSE, FALSE, 0);

    /* Stats */
    app.server_stats_label = gtk_label_new(
        "Sub-servers: 0 | Files: 0 | Up: 0 | Down: 0");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.server_stats_label),
        "circuit-label");
    gtk_widget_set_halign(app.server_stats_label,
                          GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(sub_frame),
        app.server_stats_label, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page),
        sub_frame, FALSE, FALSE, 0);

    /* 4. Onion service */
    app.server_onion_frame = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.server_onion_frame),
        "status-box");

    GtkWidget *onion_hdr = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(onion_hdr),
        gtk_label_new("\xF0\x9F\x8C\x8D"),
        FALSE, FALSE, 0);
    GtkWidget *onion_t = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(onion_t),
        "<b>Tor Onion Service</b>");
    gtk_box_pack_start(GTK_BOX(onion_hdr),
        onion_t, FALSE, FALSE, 0);

    app.server_onion_status = gtk_label_new(NULL);
    gtk_label_set_markup(
        GTK_LABEL(app.server_onion_status),
        "<span color='#707090'>Offline</span>");
    gtk_widget_set_halign(app.server_onion_status,
                          GTK_ALIGN_END);
    gtk_widget_set_hexpand(app.server_onion_status, TRUE);
    gtk_box_pack_end(GTK_BOX(onion_hdr),
        app.server_onion_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(app.server_onion_frame),
        onion_hdr, FALSE, FALSE, 0);

    GtkWidget *onion_addr_row = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    app.server_onion_label = gtk_label_new("Not running");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.server_onion_label),
        "addr-lbl");
    gtk_label_set_selectable(
        GTK_LABEL(app.server_onion_label), TRUE);
    gtk_widget_set_hexpand(app.server_onion_label, TRUE);

    app.server_onion_copy_btn = mkbtn(
        "Copy .onion", "cp-btn");
    g_signal_connect(app.server_onion_copy_btn, "clicked",
                     G_CALLBACK(on_copy_onion), NULL);

    gtk_box_pack_start(GTK_BOX(onion_addr_row),
        app.server_onion_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(onion_addr_row),
        app.server_onion_copy_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(app.server_onion_frame),
        onion_addr_row, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page),
        app.server_onion_frame, FALSE, FALSE, 0);

    /* 5. Files list */
    app.server_files_store = gtk_list_store_new(NUM_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    app.server_files_list = gtk_tree_view_new_with_model(
        GTK_TREE_MODEL(app.server_files_store));
    g_object_unref(app.server_files_store);

    GtkCellRenderer *px = gtk_cell_renderer_pixbuf_new();
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.server_files_list),
        gtk_tree_view_column_new_with_attributes(
            "", px, "icon-name", COL_ICON, NULL));
    GtkCellRenderer *tx = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *nc =
        gtk_tree_view_column_new_with_attributes(
            "File", tx, "text", COL_NAME, NULL);
    gtk_tree_view_column_set_expand(nc, TRUE);
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.server_files_list), nc);
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.server_files_list),
        gtk_tree_view_column_new_with_attributes(
            "Size", gtk_cell_renderer_text_new(),
            "text", COL_SIZE, NULL));
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.server_files_list),
        gtk_tree_view_column_new_with_attributes(
            "Chunks", gtk_cell_renderer_text_new(),
            "text", COL_PATH, NULL));
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.server_files_list),
        gtk_tree_view_column_new_with_attributes(
            "ID", gtk_cell_renderer_text_new(),
            "text", COL_ID, NULL));

    GtkWidget *fscroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(fscroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(fscroll),
        app.server_files_list);
    gtk_widget_set_vexpand(fscroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page),
        fscroll, TRUE, TRUE, 0);

    /* 6. Log */
    GtkWidget *lscroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(lscroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(
        GTK_SCROLLED_WINDOW(lscroll), 100);

    app.server_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.server_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.server_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.server_log_view),
        GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.server_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.server_log_view),
        "log-area");
    app.server_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.server_log_view));
    gtk_container_add(GTK_CONTAINER(lscroll),
        app.server_log_view);
    gtk_box_pack_start(GTK_BOX(page),
        lscroll, FALSE, FALSE, 0);

    return page;
}