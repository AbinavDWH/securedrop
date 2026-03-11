#include "gui_page_share.h"
#include "gui_helpers.h"
#include "server.h"
#include "filelist.h"
#include "util.h"

#include <dirent.h>

/* ── Helpers ───────────────────────────────────────────────── */

static GtkWidget *mkbtn(const char *label, const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* ── Callbacks ─────────────────────────────────────────────── */

static void on_add_files(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    GtkWidget *d = gtk_file_chooser_dialog_new(
        "Add Files", GTK_WINDOW(app.window),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Add", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(
        GTK_FILE_CHOOSER(d), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(
            GTK_FILE_CHOOSER(d));
        for (GSList *l = files; l; l = l->next) {
            filelist_add((char *)l->data);
            g_free(l->data);
        }
        g_slist_free(files);
        filelist_refresh_view();
    }
    gtk_widget_destroy(d);
}

static void on_add_folder(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    GtkWidget *d = gtk_file_chooser_dialog_new(
        "Add Folder", GTK_WINDOW(app.window),
        GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Add", GTK_RESPONSE_ACCEPT, NULL);

    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(
            GTK_FILE_CHOOSER(d));
        if (f) {
            filelist_add_dir(f);
            g_free(f);
        }
        filelist_refresh_view();
    }
    gtk_widget_destroy(d);
}

static void on_remove(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(app.share_file_list));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        char *path = NULL;
        gtk_tree_model_get(model, &iter, COL_PATH, &path, -1);
        if (path) {
            filelist_remove(path);
            g_free(path);
        }
        filelist_refresh_view();
    }
}

static void on_clear(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    filelist_clear();
    filelist_refresh_view();
}

static void on_start(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    server_start(LOG_SHARE);
    gtk_widget_set_sensitive(app.share_start_btn, FALSE);
    gtk_widget_set_sensitive(app.share_stop_btn, TRUE);
    gtk_widget_show(app.share_status_box);
}

static void on_stop(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    server_stop(LOG_SHARE);
    gtk_widget_set_sensitive(app.share_start_btn, TRUE);
    gtk_widget_set_sensitive(app.share_stop_btn, FALSE);
    gtk_widget_hide(app.share_status_box);
}

static void on_copy_addr(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    const char *text = gtk_label_get_text(
        GTK_LABEL(app.share_addr_label));
    gtk_clipboard_set_text(
        gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), text, -1);
    gui_post_log(LOG_SHARE, "Address copied to clipboard");
}

static void on_drag_recv(GtkWidget *w, GdkDragContext *ctx,
                         int x, int y,
                         GtkSelectionData *data,
                         guint info, guint t, gpointer u)
{
    (void)w; (void)x; (void)y; (void)info; (void)u;
    char **uris = gtk_selection_data_get_uris(data);
    if (uris) {
        for (int j = 0; uris[j]; j++) {
            char *path = g_filename_from_uri(uris[j], NULL, NULL);
            if (path) {
                struct stat st;
                if (stat(path, &st) == 0) {
                    if (S_ISDIR(st.st_mode))
                        filelist_add_dir(path);
                    else
                        filelist_add(path);
                }
                g_free(path);
            }
        }
        g_strfreev(uris);
        filelist_refresh_view();
    }
    gtk_drag_finish(ctx, TRUE, FALSE, t);
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_share_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(page), 14);

    /* Header */
    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *icon = gtk_image_new_from_icon_name(
        "folder-publicshare", GTK_ICON_SIZE_DND);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<b>Share Files</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title), "sec-title");
    gtk_box_pack_start(GTK_BOX(hdr), icon, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hdr), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), hdr, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new(
        "End-to-end encrypted file sharing with "
        "distributed storage");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub), "dim-text");
    gtk_widget_set_halign(sub, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), sub, FALSE, FALSE, 0);

    /* File area with drag-and-drop */
    GtkWidget *file_area = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(file_area, TRUE);

    GtkTargetEntry targets[] = {{"text/uri-list", 0, 0}};
    gtk_drag_dest_set(file_area, GTK_DEST_DEFAULT_ALL,
                      targets, 1, GDK_ACTION_COPY);
    g_signal_connect(file_area, "drag-data-received",
                     G_CALLBACK(on_drag_recv), NULL);

    /* Drag placeholder */
    app.share_drag_area = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(app.share_drag_area),
        "\n\n<b>Drop files here</b>\n"
        "<small>or use the buttons below</small>");
    gtk_label_set_justify(
        GTK_LABEL(app.share_drag_area), GTK_JUSTIFY_CENTER);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.share_drag_area),
        "drag-text");
    gtk_widget_set_valign(app.share_drag_area, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(app.share_drag_area, TRUE);

    /* File list tree view */
    app.share_store = gtk_list_store_new(
        NUM_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    app.share_file_list = gtk_tree_view_new_with_model(
        GTK_TREE_MODEL(app.share_store));
    g_object_unref(app.share_store);

    GtkCellRenderer *pix = gtk_cell_renderer_pixbuf_new();
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.share_file_list),
        gtk_tree_view_column_new_with_attributes(
            "", pix, "icon-name", COL_ICON, NULL));

    GtkCellRenderer *txt = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *name_col =
        gtk_tree_view_column_new_with_attributes(
            "Name", txt, "text", COL_NAME, NULL);
    gtk_tree_view_column_set_expand(name_col, TRUE);
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.share_file_list), name_col);

    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.share_file_list),
        gtk_tree_view_column_new_with_attributes(
            "Size", gtk_cell_renderer_text_new(),
            "text", COL_SIZE, NULL));

    app.share_file_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(app.share_file_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(app.share_file_scroll),
                      app.share_file_list);
    gtk_widget_set_vexpand(app.share_file_scroll, TRUE);
    gtk_widget_set_no_show_all(app.share_file_scroll, TRUE);

    gtk_box_pack_start(GTK_BOX(file_area),
                       app.share_drag_area, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(file_area),
                       app.share_file_scroll, TRUE, TRUE, 0);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(file_area), "drag-zone");
    gtk_box_pack_start(GTK_BOX(page), file_area, TRUE, TRUE, 0);

    /* Button bar */
    GtkWidget *btn_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 4);

    app.share_add_btn = mkbtn("Add Files", "sec-btn");
    app.share_add_folder_btn = mkbtn("Add Folder", "sec-btn");
    app.share_remove_btn = mkbtn("Remove", "sec-btn");
    app.share_clear_btn = mkbtn("Clear", "sec-btn");

    g_signal_connect(app.share_add_btn, "clicked",
                     G_CALLBACK(on_add_files), NULL);
    g_signal_connect(app.share_add_folder_btn, "clicked",
                     G_CALLBACK(on_add_folder), NULL);
    g_signal_connect(app.share_remove_btn, "clicked",
                     G_CALLBACK(on_remove), NULL);
    g_signal_connect(app.share_clear_btn, "clicked",
                     G_CALLBACK(on_clear), NULL);

    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_add_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_add_folder_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_remove_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_clear_btn, FALSE, FALSE, 0);

    /* Spacer */
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       gtk_label_new(""), TRUE, TRUE, 0);

    app.share_start_btn = mkbtn("Start Server", "act-btn");
    app.share_stop_btn = mkbtn("Stop", "stop-btn");
    gtk_widget_set_sensitive(app.share_stop_btn, FALSE);

    g_signal_connect(app.share_start_btn, "clicked",
                     G_CALLBACK(on_start), NULL);
    g_signal_connect(app.share_stop_btn, "clicked",
                     G_CALLBACK(on_stop), NULL);

    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_start_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.share_stop_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page), btn_bar, FALSE, FALSE, 0);

    /* Status box */
    app.share_status_box = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.share_status_box),
        "status-box");
    gtk_widget_set_no_show_all(app.share_status_box, TRUE);

    GtkWidget *st_lbl = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(st_lbl),
                         "<b>Server Active</b>");
    gtk_widget_set_halign(st_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(app.share_status_box),
                       st_lbl, FALSE, FALSE, 0);

    GtkWidget *addr_box = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);
    app.share_addr_label = gtk_label_new("Offline");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.share_addr_label),
        "addr-lbl");
    gtk_label_set_selectable(
        GTK_LABEL(app.share_addr_label), TRUE);
    gtk_widget_set_hexpand(app.share_addr_label, TRUE);

    app.share_copy_btn = mkbtn("Copy", "cp-btn");
    g_signal_connect(app.share_copy_btn, "clicked",
                     G_CALLBACK(on_copy_addr), NULL);

    gtk_box_pack_start(GTK_BOX(addr_box),
                       app.share_addr_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(addr_box),
                       app.share_copy_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(app.share_status_box),
                       addr_box, FALSE, FALSE, 0);

    /* Download count */
    GtkWidget *dl_row = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(dl_row),
        gtk_label_new("Downloads:"), FALSE, FALSE, 0);
    app.share_dl_label = gtk_label_new("0");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.share_dl_label),
        "stat-num");
    gtk_box_pack_start(GTK_BOX(dl_row),
                       app.share_dl_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(app.share_status_box),
                       dl_row, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page),
                       app.share_status_box, FALSE, FALSE, 0);

    /* Progress bar */
    app.share_progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(page),
                       app.share_progress, FALSE, FALSE, 0);

    /* Log area */
    GtkWidget *log_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(
        GTK_SCROLLED_WINDOW(log_scroll), 100);

    app.share_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.share_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.share_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.share_log_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.share_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.share_log_view),
        "log-area");

    app.share_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.share_log_view));
    gtk_container_add(GTK_CONTAINER(log_scroll),
                      app.share_log_view);
    gtk_box_pack_start(GTK_BOX(page),
                       log_scroll, FALSE, FALSE, 0);

    return page;
}