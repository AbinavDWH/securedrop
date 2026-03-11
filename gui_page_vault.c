#include "gui_page_vault.h"
#include "gui_helpers.h"
#include "crypto.h"
#include "util.h"

#include <dirent.h>

static GtkWidget *mkbtn(const char *label, const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* ── Refresh vault file list ───────────────────────────────── */

static void refresh_vault(void)
{
    gtk_list_store_clear(app.vault_store);
    mkdir_p(VAULT_DIR, 0700);

    DIR *d = opendir(VAULT_DIR);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char fp[4096];
        snprintf(fp, sizeof(fp), "%s/%s", VAULT_DIR, e->d_name);

        struct stat st;
        if (stat(fp, &st) != 0) continue;

        char sz[64];
        human_size((size_t)st.st_size, sz, sizeof(sz));

        GtkTreeIter iter;
        gtk_list_store_append(app.vault_store, &iter);
        gtk_list_store_set(app.vault_store, &iter,
            COL_ICON,   "channel-secure-symbolic",
            COL_NAME,   e->d_name,
            COL_SIZE,   sz,
            COL_PATH,   fp,
            COL_STATUS, "Encrypted",
            -1);
    }
    closedir(d);
}

/* ── Callbacks ─────────────────────────────────────────────── */

static void on_add(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Encrypt File", GTK_WINDOW(app.window),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Encrypt", GTK_RESPONSE_ACCEPT, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *src = gtk_file_chooser_get_filename(
            GTK_FILE_CHOOSER(dlg));
        if (src) {
            mkdir_p(VAULT_DIR, 0700);

            const char *bn = strrchr(src, '/');
            bn = bn ? bn + 1 : src;

            char dst[4096];
            snprintf(dst, sizeof(dst),
                     "%s/%s.enc", VAULT_DIR, bn);

            /* Ensure RSA keys exist */
            if (!file_exists(RSA_PUB_FILE))
                gen_rsa_keys_to_file(RSA_PUB_FILE, RSA_PRIV_FILE);

            gui_post_log(LOG_VAULT, "Encrypting: %s", bn);

            if (vault_encrypt_file(src, dst) == 0)
                gui_post_log(LOG_VAULT, "Stored: %s", dst);
            else
                gui_post_log(LOG_VAULT, "Encryption failed");

            g_free(src);
            refresh_vault();
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_export(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    GtkTreeSelection *sel = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(app.vault_list));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gui_post_log(LOG_VAULT, "Select a file first");
        return;
    }

    char *path = NULL, *name = NULL;
    gtk_tree_model_get(model, &iter,
        COL_PATH, &path, COL_NAME, &name, -1);

    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Export Decrypted", GTK_WINDOW(app.window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT, NULL);

    /* Remove .enc suffix for suggested name */
    char suggested[512];
    strncpy(suggested, name, sizeof(suggested) - 1);
    suggested[sizeof(suggested) - 1] = '\0';
    size_t slen = strlen(suggested);
    if (slen > 4 && strcmp(suggested + slen - 4, ".enc") == 0)
        suggested[slen - 4] = '\0';

    gtk_file_chooser_set_current_name(
        GTK_FILE_CHOOSER(dlg), suggested);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *dst = gtk_file_chooser_get_filename(
            GTK_FILE_CHOOSER(dlg));
        if (dst) {
            gui_post_log(LOG_VAULT, "Decrypting: %s", name);

            if (vault_decrypt_file(path, dst) == 0)
                gui_post_log(LOG_VAULT, "Exported: %s", dst);
            else
                gui_post_log(LOG_VAULT,
                    "Decryption failed — integrity check "
                    "may have failed");

            g_free(dst);
        }
    }

    g_free(path);
    g_free(name);
    gtk_widget_destroy(dlg);
}

static void on_delete(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    GtkTreeSelection *sel = gtk_tree_view_get_selection(
        GTK_TREE_VIEW(app.vault_list));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        char *path = NULL;
        gtk_tree_model_get(model, &iter,
                           COL_PATH, &path, -1);
        if (path) {
            unlink(path);
            gui_post_log(LOG_VAULT, "Deleted: %s", path);
            g_free(path);
            refresh_vault();
        }
    }
}

/* ── Build page ────────────────────────────────────────────── */

GtkWidget *gui_build_vault_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(page), 14);

    /* Header */
    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(hdr),
        gtk_image_new_from_icon_name(
            "security-high", GTK_ICON_SIZE_DND),
        FALSE, FALSE, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<b>Secure Vault</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title), "sec-title");
    gtk_box_pack_start(GTK_BOX(hdr), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), hdr, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new(
        "AES-256-GCM encrypted local storage with "
        "RSA-wrapped keys");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub), "dim-text");
    gtk_widget_set_halign(sub, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), sub, FALSE, FALSE, 0);

    /* Buttons */
    GtkWidget *btn_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 4);

    app.vault_add_btn = mkbtn("Encrypt File", "act-btn");
    app.vault_export_btn = mkbtn("Decrypt Export", "sec-btn");
    app.vault_delete_btn = mkbtn("Delete", "stop-btn");

    g_signal_connect(app.vault_add_btn, "clicked",
                     G_CALLBACK(on_add), NULL);
    g_signal_connect(app.vault_export_btn, "clicked",
                     G_CALLBACK(on_export), NULL);
    g_signal_connect(app.vault_delete_btn, "clicked",
                     G_CALLBACK(on_delete), NULL);

    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.vault_add_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.vault_export_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
                       app.vault_delete_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page),
                       btn_bar, FALSE, FALSE, 0);

    /* File list */
    app.vault_store = gtk_list_store_new(
        NUM_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    app.vault_list = gtk_tree_view_new_with_model(
        GTK_TREE_MODEL(app.vault_store));
    g_object_unref(app.vault_store);

    GtkCellRenderer *pix = gtk_cell_renderer_pixbuf_new();
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.vault_list),
        gtk_tree_view_column_new_with_attributes(
            "", pix, "icon-name", COL_ICON, NULL));

    GtkCellRenderer *txt = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *nc =
        gtk_tree_view_column_new_with_attributes(
            "Name", txt, "text", COL_NAME, NULL);
    gtk_tree_view_column_set_expand(nc, TRUE);
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.vault_list), nc);

    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.vault_list),
        gtk_tree_view_column_new_with_attributes(
            "Size", gtk_cell_renderer_text_new(),
            "text", COL_SIZE, NULL));
    gtk_tree_view_append_column(
        GTK_TREE_VIEW(app.vault_list),
        gtk_tree_view_column_new_with_attributes(
            "Status", gtk_cell_renderer_text_new(),
            "text", COL_STATUS, NULL));

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), app.vault_list);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page), scroll, TRUE, TRUE, 0);

    /* Log */
    GtkWidget *log_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(
        GTK_SCROLLED_WINDOW(log_scroll), 80);

    app.vault_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.vault_log_view), FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.vault_log_view), FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.vault_log_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.vault_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(app.vault_log_view),
        "log-area");

    app.vault_log_buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(app.vault_log_view));
    gtk_container_add(GTK_CONTAINER(log_scroll),
                      app.vault_log_view);
    gtk_box_pack_start(GTK_BOX(page),
                       log_scroll, FALSE, FALSE, 0);

    refresh_vault();
    return page;
}