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

#include "gui_page_advanced.h"
#include "gui_helpers.h"
#include "advanced_config.h"
#include "util.h"

/* ── Helpers ───────────────────────────────────────────────── */

static GtkWidget *mkbtn(const char *label,
                        const char *cls)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(b), cls);
    return b;
}

/* Parse an integer from a GTK entry.
   Returns 1 on success, 0 on failure (non-numeric).
   On empty input, *out = default_val and returns 1. */
static int parse_entry_int(GtkWidget *entry,
                           int default_val,
                           int *out)
{
    const char *text = gtk_entry_get_text(
        GTK_ENTRY(entry));

    if (!text || !*text) {
        *out = default_val;
        return 1;
    }

    /* Check every char is digit or leading minus */
    const char *p = text;
    if (*p == '-') p++;
    if (!*p) return 0;  /* just a minus sign */
    for (; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
    }

    *out = atoi(text);
    return 1;
}

/* ── Apply callback ────────────────────────────────────────── */

static void on_apply(GtkButton *b, gpointer u)
{
    (void)b; (void)u;
    int errors = 0;
    int val;

    gui_post_log(LOG_ADVANCED,
        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 "
        "Validating settings "
        "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80");

    /* ── Chunks per sub-server ────────────── */
    if (!parse_entry_int(
            app.adv_chunks_per_sub_entry,
            1, &val)) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x97 Chunks/sub: "
            "non-numeric input");
        errors++;
    } else {
        if (val < 1 || val > 8) {
            int clamped =
                adv_config_clamp(val, 1, 8);
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Chunks/sub: %d "
                "out of range [1\xe2\x80\x93" "8], "
                "clamped to %d",
                val, clamped);
            val = clamped;
            char buf[16];
            snprintf(buf, sizeof(buf),
                     "%d", val);
            gtk_entry_set_text(
                GTK_ENTRY(
                    app.adv_chunks_per_sub_entry),
                buf);
        }
        adv_config.chunks_per_sub = val;
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 Chunks/sub: %d", val);
    }

    /* ── Retry timeout ────────────────────── */
    if (!parse_entry_int(
            app.adv_retry_timeout_entry,
            60, &val)) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x97 Retry timeout: "
            "non-numeric input");
        errors++;
    } else {
        if (val < 15 || val > 300) {
            int clamped =
                adv_config_clamp(val, 15, 300);
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Retry timeout: %d "
                "out of range [15\xe2\x80\x93" "300]s, "
                "clamped to %d",
                val, clamped);
            val = clamped;
            char buf[16];
            snprintf(buf, sizeof(buf),
                     "%d", val);
            gtk_entry_set_text(
                GTK_ENTRY(
                    app.adv_retry_timeout_entry),
                buf);
        }
        adv_config.retry_timeout_sec = val;
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 Retry timeout: %ds",
            val);
    }

    /* ── Max retries ──────────────────────── */
    if (!parse_entry_int(
            app.adv_max_retries_entry,
            4, &val)) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x97 Max retries: "
            "non-numeric input");
        errors++;
    } else {
        if (val < 1 || val > 10) {
            int clamped =
                adv_config_clamp(val, 1, 10);
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Max retries: %d "
                "out of range [1\xe2\x80\x93" "10], "
                "clamped to %d",
                val, clamped);
            val = clamped;
            char buf[16];
            snprintf(buf, sizeof(buf),
                     "%d", val);
            gtk_entry_set_text(
                GTK_ENTRY(
                    app.adv_max_retries_entry),
                buf);
        }
        adv_config.max_retries = val;
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 Max retries: %d", val);
    }

    /* ── Download threads ─────────────────── */
    if (!parse_entry_int(
            app.adv_thread_count_entry,
            0, &val)) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x97 Threads: "
            "non-numeric input");
        errors++;
    } else {
        if (val < 0 || val > 128) {
            int clamped =
                adv_config_clamp(val, 0, 128);
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Threads: %d "
                "out of range [0\xe2\x80\x93" "128], "
                "clamped to %d",
                val, clamped);
            val = clamped;
            char buf[16];
            snprintf(buf, sizeof(buf),
                     "%d", val);
            gtk_entry_set_text(
                GTK_ENTRY(
                    app.adv_thread_count_entry),
                buf);
        }
        adv_config.download_threads = val;
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 Threads: %s%d",
            val == 0 ? "auto (" : "",
            val);
        if (val == 0)
            gui_post_log(LOG_ADVANCED,
                "  auto = system decides)");
    }

    /* ── Warmup stagger ───────────────────── */
    if (!parse_entry_int(
            app.adv_warmup_stagger_entry,
            500, &val)) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x97 Warmup stagger: "
            "non-numeric input");
        errors++;
    } else {
        if (val < 100 || val > 5000) {
            int clamped =
                adv_config_clamp(val, 100, 5000);
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Warmup stagger: %d "
                "out of range "
                "[100\xe2\x80\x93" "5000]ms, "
                "clamped to %d",
                val, clamped);
            val = clamped;
            char buf[16];
            snprintf(buf, sizeof(buf),
                     "%d", val);
            gtk_entry_set_text(
                GTK_ENTRY(
                    app.adv_warmup_stagger_entry),
                buf);
        }
        adv_config.warmup_stagger_ms = val;
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 Warmup stagger: %dms",
            val);
    }

    /* ── Summary ──────────────────────────── */
    if (errors > 0) {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9a\xa0 %d field(s) had errors "
            "\xe2\x80\x94 fix and retry",
            errors);
    } else {
        gui_post_log(LOG_ADVANCED,
            "\xe2\x9c\x93 All settings applied "
            "successfully");
        gui_post_log(LOG_ADVANCED,
            "  chunks/sub=%d  "
            "timeout=%ds  "
            "retries=%d  "
            "threads=%s  "
            "stagger=%dms",
            adv_config.chunks_per_sub,
            adv_config.retry_timeout_sec,
            adv_config.max_retries,
            adv_config.download_threads == 0
                ? "auto" : "custom",
            adv_config.warmup_stagger_ms);

        /* Persist to disk */
        if (adv_config_save() == 0)
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9c\x93 Settings saved to disk");
        else
            gui_post_log(LOG_ADVANCED,
                "\xe2\x9a\xa0 Could not save to disk");
    }
}

/* ── Reset callback ────────────────────────────────────────── */

static void on_reset(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    adv_config_reset();

    gtk_entry_set_text(
        GTK_ENTRY(app.adv_chunks_per_sub_entry),
        "1");
    gtk_entry_set_text(
        GTK_ENTRY(app.adv_retry_timeout_entry),
        "60");
    gtk_entry_set_text(
        GTK_ENTRY(app.adv_max_retries_entry),
        "4");
    gtk_entry_set_text(
        GTK_ENTRY(app.adv_thread_count_entry),
        "0");
    gtk_entry_set_text(
        GTK_ENTRY(app.adv_warmup_stagger_entry),
        "500");

    gui_post_log(LOG_ADVANCED,
        "\xe2\x9c\x93 All settings reset "
        "to defaults");

    /* Persist defaults to disk */
    adv_config_save();
}

/* ══════════════════════════════════════════════════════════════
 * BUILD PAGE
 * ══════════════════════════════════════════════════════════════ */

static GtkWidget *make_setting_row(
    GtkWidget *grid, int row,
    const char *label_text,
    const char *hint_text,
    const char *default_val,
    int width_chars,
    GtkWidget **entry_out)
{
    GtkWidget *lbl = gtk_label_new(label_text);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(lbl),
        "dim-text");
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(GTK_GRID(grid),
        lbl, 0, row, 1, 1);

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_text(
        GTK_ENTRY(entry), default_val);
    gtk_entry_set_placeholder_text(
        GTK_ENTRY(entry), default_val);
    gtk_entry_set_width_chars(
        GTK_ENTRY(entry), width_chars);
    gtk_entry_set_max_length(
        GTK_ENTRY(entry), 6);
    gtk_widget_set_hexpand(entry, FALSE);
    gtk_grid_attach(GTK_GRID(grid),
        entry, 1, row, 1, 1);

    GtkWidget *hint = gtk_label_new(hint_text);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(hint),
        "dim-text");
    gtk_widget_set_halign(hint, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid),
        hint, 2, row, 1, 1);

    *entry_out = entry;
    return entry;
}

GtkWidget *gui_build_advanced_page(void)
{
    GtkWidget *page = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(
        GTK_CONTAINER(page), 20);

    /* ── Header ─────────────────────────────── */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        "<b>Advanced Configuration</b>");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(title),
        "sec-title");
    gtk_widget_set_halign(title,
        GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page),
        title, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new(
        "Fine-tune chunk distribution, "
        "network retry behavior, and "
        "parallelism settings. "
        "Invalid inputs are "
        "automatically clamped to "
        "safe ranges.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(sub),
        "page-subtitle");
    gtk_widget_set_halign(sub,
        GTK_ALIGN_START);
    gtk_label_set_line_wrap(
        GTK_LABEL(sub), TRUE);
    gtk_box_pack_start(GTK_BOX(page),
        sub, FALSE, FALSE, 0);

    /* ══ Section 1: Chunk Distribution ══════ */

    GtkWidget *chunk_box = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(chunk_box),
        "status-box");

    GtkWidget *chunk_title = gtk_label_new(NULL);
    gtk_label_set_markup(
        GTK_LABEL(chunk_title),
        "<b>Chunk Distribution</b>");
    gtk_widget_set_halign(chunk_title,
        GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(chunk_box),
        chunk_title, FALSE, FALSE, 0);

    GtkWidget *chunk_desc = gtk_label_new(
        "Pack multiple chunks per sub-server. "
        "Value of 1 = standard round-robin, "
        "2\xe2\x80\x93" "8 = group N consecutive "
        "chunks on the same sub-server.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(chunk_desc),
        "dim-text");
    gtk_widget_set_halign(chunk_desc,
        GTK_ALIGN_START);
    gtk_label_set_line_wrap(
        GTK_LABEL(chunk_desc), TRUE);
    gtk_box_pack_start(GTK_BOX(chunk_box),
        chunk_desc, FALSE, FALSE, 0);

    GtkWidget *cg = gtk_grid_new();
    gtk_grid_set_row_spacing(
        GTK_GRID(cg), 8);
    gtk_grid_set_column_spacing(
        GTK_GRID(cg), 10);

    /* Use adv_config values (may be loaded from disk) */
    char buf_cps[8];
    snprintf(buf_cps, sizeof(buf_cps), "%d",
        adv_config.chunks_per_sub);

    make_setting_row(cg, 0,
        "Chunks/Sub:",
        "Range: 1\xe2\x80\x93" "8",
        buf_cps, 4,
        &app.adv_chunks_per_sub_entry);

    gtk_box_pack_start(GTK_BOX(chunk_box),
        cg, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page),
        chunk_box, FALSE, FALSE, 0);

    /* ══ Section 2: Network Tuning ══════════ */

    GtkWidget *net_box = gtk_box_new(
        GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(net_box),
        "status-box");

    GtkWidget *net_title = gtk_label_new(NULL);
    gtk_label_set_markup(
        GTK_LABEL(net_title),
        "<b>Network Tuning</b>");
    gtk_widget_set_halign(net_title,
        GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(net_box),
        net_title, FALSE, FALSE, 0);

    GtkWidget *net_desc = gtk_label_new(
        "Control retry behavior and "
        "thread parallelism for "
        "chunk transfers over Tor.");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(net_desc),
        "dim-text");
    gtk_widget_set_halign(net_desc,
        GTK_ALIGN_START);
    gtk_label_set_line_wrap(
        GTK_LABEL(net_desc), TRUE);
    gtk_box_pack_start(GTK_BOX(net_box),
        net_desc, FALSE, FALSE, 0);

    GtkWidget *ng = gtk_grid_new();
    gtk_grid_set_row_spacing(
        GTK_GRID(ng), 8);
    gtk_grid_set_column_spacing(
        GTK_GRID(ng), 10);

    char buf_rt[8], buf_mr[8], buf_dt[8], buf_ws[8];
    snprintf(buf_rt, sizeof(buf_rt), "%d",
        adv_config.retry_timeout_sec);
    snprintf(buf_mr, sizeof(buf_mr), "%d",
        adv_config.max_retries);
    snprintf(buf_dt, sizeof(buf_dt), "%d",
        adv_config.download_threads);
    snprintf(buf_ws, sizeof(buf_ws), "%d",
        adv_config.warmup_stagger_ms);

    make_setting_row(ng, 0,
        "Retry Timeout:",
        "15\xe2\x80\x93" "300 seconds",
        buf_rt, 5,
        &app.adv_retry_timeout_entry);

    make_setting_row(ng, 1,
        "Max Retries:",
        "1\xe2\x80\x93" "10 attempts",
        buf_mr, 4,
        &app.adv_max_retries_entry);

    make_setting_row(ng, 2,
        "Download Threads:",
        "0 = auto, 1\xe2\x80\x93" "128",
        buf_dt, 5,
        &app.adv_thread_count_entry);

    make_setting_row(ng, 3,
        "Warmup Stagger:",
        "100\xe2\x80\x93" "5000 ms",
        buf_ws, 6,
        &app.adv_warmup_stagger_entry);

    gtk_box_pack_start(GTK_BOX(net_box),
        ng, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page),
        net_box, FALSE, FALSE, 0);

    /* ══ Section 3: Controls ════════════════ */

    GtkWidget *btn_bar = gtk_box_new(
        GTK_ORIENTATION_HORIZONTAL, 6);

    app.adv_apply_btn = mkbtn(
        "Apply Settings", "act-btn");
    g_signal_connect(app.adv_apply_btn,
        "clicked",
        G_CALLBACK(on_apply), NULL);

    app.adv_reset_btn = mkbtn(
        "Reset to Defaults", "sec-btn");
    g_signal_connect(app.adv_reset_btn,
        "clicked",
        G_CALLBACK(on_reset), NULL);

    gtk_box_pack_start(GTK_BOX(btn_bar),
        app.adv_apply_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_bar),
        app.adv_reset_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page),
        btn_bar, FALSE, FALSE, 4);

    /* ══ Log View ═══════════════════════════ */

    GtkWidget *log_scroll =
        gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(log_scroll),
        GTK_POLICY_AUTOMATIC,
        GTK_POLICY_AUTOMATIC);

    app.adv_log_view = gtk_text_view_new();
    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(app.adv_log_view),
        FALSE);
    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(app.adv_log_view),
        FALSE);
    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(app.adv_log_view),
        GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(
        GTK_TEXT_VIEW(app.adv_log_view), 6);
    gtk_style_context_add_class(
        gtk_widget_get_style_context(
            app.adv_log_view),
        "log-area");

    app.adv_log_buf =
        gtk_text_view_get_buffer(
            GTK_TEXT_VIEW(app.adv_log_view));
    gtk_container_add(
        GTK_CONTAINER(log_scroll),
        app.adv_log_view);
    gtk_widget_set_vexpand(log_scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page),
        log_scroll, TRUE, TRUE, 0);

    return page;
}
