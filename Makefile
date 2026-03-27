# SecureDrop — Encrypted File Sharing over Tor
# Copyright (C) 2026  Abinav
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# ══════════════════════════════════════════════════════════════
# SecureDrop v5.0 — Build System
# ══════════════════════════════════════════════════════════════

CC       = gcc

CFLAGS   = -Wall -Wextra -Wno-unused-parameter -O2 -g \
           $(shell pkg-config --cflags gtk+-3.0) \
           -D_GNU_SOURCE \
           -fstack-protector-strong \
           -fPIE \
           -D_FORTIFY_SOURCE=2 \
           -Wformat \
           -Wformat-security \
           -Werror=format-security \
           -fstack-clash-protection \
           -fcf-protection \
           -Wl,-z,noexecstack

LDFLAGS  = $(shell pkg-config --libs gtk+-3.0) \
           -lmicrohttpd \
           -lcurl \
           -lssl \
           -lcrypto \
           -lpthread \
           -lm \
           -pie \
           -Wl,-z,relro \
           -Wl,-z,now \
           -Wl,-z,noexecstack

# ── Source files ───────────────────────────────────────────────
SRCS = main.c \
       util.c \
       crypto.c \
       network.c \
       tor.c \
       filelist.c \
       gui_helpers.c \
       gui_css.c \
       gui_page_share.c \
       gui_page_recv.c \
       gui_page_send.c \
       gui_page_vault.c \
       gui_page_server.c \
       gui.c \
       protocol.c \
       storage.c \
       server.c \
       client.c \
       onion.c \
		parallel.c \
       tor_pool.c\
	    sub_tor.c \
       p2p.c \
       gui_page_p2p.c \
       advanced_config.c \
       gui_page_advanced.c

OBJS     = $(SRCS:.c=.o)
TARGET   = securedrop
RELEASE  = securedrop.bin

# ── Directories ────────────────────────────────────────────────
VAULT_DIR   = secure_vault
STORE_DIR   = chunk_store
OUTPUT_DIR  = received_files
META_DIR    = file_meta
TOR_DIR     = tor_data

# ══════════════════════════════════════════════════════════════
# Targets
# ══════════════════════════════════════════════════════════════

.PHONY: all clean release dirs install-deps check run \
        distclean purge help

all: dirs $(TARGET)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "  Build complete: ./$(TARGET)"
	@echo "  Run:   ./$(TARGET)"
	@echo "  Strip: make release"
	@echo "════════════════════════════════════════"

# ── Create required directories ────────────────────────────────
KEY_DIR     = keys

dirs:
	@mkdir -p $(VAULT_DIR) $(STORE_DIR) $(OUTPUT_DIR) \
	          $(META_DIR) $(TOR_DIR) $(KEY_DIR) 2>/dev/null || true
	@chmod 700 $(VAULT_DIR) $(STORE_DIR) $(KEY_DIR) \
	           $(META_DIR) $(TOR_DIR) 2>/dev/null || true
	@chmod 755 $(OUTPUT_DIR) 2>/dev/null || true

# ── Link ───────────────────────────────────────────────────────
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# ── Compile ────────────────────────────────────────────────────
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Stripped release binary ────────────────────────────────────
release: $(TARGET)
	strip -s $(TARGET) -o $(RELEASE)
	chmod 755 $(RELEASE)
	@echo ""
	@echo "Release binary: $(RELEASE)"
	@ls -lh $(RELEASE)
	@echo ""
	@echo "Security checks:"
	@readelf -l $(RELEASE) 2>/dev/null | grep -q "GNU_STACK.*RW " \
		&& echo "  [WARN] Executable stack detected" \
		|| echo "  [OK]   Non-executable stack"
	@readelf -d $(RELEASE) 2>/dev/null | grep -q "BIND_NOW" \
		&& echo "  [OK]   Full RELRO" \
		|| echo "  [WARN] Partial RELRO"
	@file $(RELEASE) | grep -q "pie" \
		&& echo "  [OK]   PIE enabled (ASLR)" \
		|| echo "  [WARN] PIE not detected"

# ── Run ────────────────────────────────────────────────────────
run: all
	./$(TARGET)

# ── Install dependencies (Debian/Ubuntu) ──────────────────────
install-deps:
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		pkg-config \
		libgtk-3-dev \
		libmicrohttpd-dev \
		libcurl4-openssl-dev \
		libssl-dev \
		tor
	@echo ""
	@echo "All dependencies installed."

# ── Check that all dependencies are available ──────────────────
check:
	@echo "Checking dependencies..."
	@pkg-config --exists gtk+-3.0 \
		&& echo "  [OK] gtk+-3.0" \
		|| echo "  [MISSING] gtk+-3.0 — sudo apt install libgtk-3-dev"
	@pkg-config --exists libmicrohttpd \
		&& echo "  [OK] libmicrohttpd" \
		|| echo "  [MISSING] libmicrohttpd — sudo apt install libmicrohttpd-dev"
	@pkg-config --exists libcurl \
		&& echo "  [OK] libcurl" \
		|| echo "  [MISSING] libcurl — sudo apt install libcurl4-openssl-dev"
	@pkg-config --exists openssl \
		&& echo "  [OK] openssl" \
		|| echo "  [MISSING] openssl — sudo apt install libssl-dev"
	@which tor > /dev/null 2>&1 \
		&& echo "  [OK] tor binary" \
		|| echo "  [MISSING] tor — sudo apt install tor"
	@which gcc > /dev/null 2>&1 \
		&& echo "  [OK] gcc" \
		|| echo "  [MISSING] gcc — sudo apt install build-essential"
	@echo "Done."

# ── Clean build artifacts ──────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET) $(RELEASE)

# ── Clean everything including data directories ────────────────
distclean: clean
	rm -rf $(VAULT_DIR) $(STORE_DIR) $(OUTPUT_DIR) \
	       $(META_DIR) $(TOR_DIR)
	rm -rf keys/

# ── Nuclear option — remove all generated files ────────────────
purge: distclean
	rm -rf tor_data/
	@echo "All data purged."

# ── Help ───────────────────────────────────────────────────────
help:
	@echo ""
	@echo "SecureDrop v4.0 — Build Targets"
	@echo "═══════════════════════════════════════════"
	@echo ""
	@echo "  make              Build the application"
	@echo "  make run          Build and run"
	@echo "  make release      Build stripped binary"
	@echo "  make check        Verify dependencies"
	@echo "  make install-deps Install all dependencies"
	@echo "  make clean        Remove build artifacts"
	@echo "  make distclean    Remove build + data dirs"
	@echo "  make purge        Remove everything"
	@echo "  make help         Show this message"
	@echo ""

# ══════════════════════════════════════════════════════════════
# Header dependencies
# ══════════════════════════════════════════════════════════════

main.o:            main.c app.h gui.h tor.h storage.h onion.h p2p.h advanced_config.h

util.o:            util.c util.h app.h

crypto.o:          crypto.c crypto.h util.h app.h

network.o:         network.c network.h app.h

tor.o:             tor.c tor.h app.h

filelist.o:        filelist.c filelist.h util.h app.h

gui_helpers.o:     gui_helpers.c gui_helpers.h util.h app.h

gui_css.o:         gui_css.c gui_css.h

gui_page_share.o:  gui_page_share.c gui_page_share.h gui_helpers.h server.h filelist.h util.h app.h

gui_page_recv.o:   gui_page_recv.c gui_page_recv.h gui_helpers.h client.h tor.h util.h app.h

gui_page_send.o:   gui_page_send.c gui_page_send.h gui_helpers.h client.h tor.h crypto.h util.h app.h

gui_page_vault.o:  gui_page_vault.c gui_page_vault.h gui_helpers.h crypto.h util.h app.h

gui_page_server.o: gui_page_server.c gui_page_server.h gui_helpers.h server.h storage.h onion.h util.h app.h


protocol.o:        protocol.c protocol.h storage.h crypto.h util.h gui_helpers.h app.h

storage.o:         storage.c storage.h crypto.h util.h gui_helpers.h app.h

server.o:   server.c server.h protocol.h storage.h network.h gui_helpers.h crypto.h util.h onion.h parallel.h sub_tor.h app.h

onion.o:           onion.c onion.h gui_helpers.h util.h app.h

tor_pool.o:        tor_pool.c tor_pool.h gui_helpers.h util.h app.h

parallel.o:        parallel.c parallel.h gui_helpers.h util.h tor.h app.h

client.o:          client.c client.h protocol.h crypto.h gui_helpers.h util.h tor.h parallel.h tor_pool.h app.h

sub_tor.o:  sub_tor.c sub_tor.h gui_helpers.h util.h app.h

p2p.o:             p2p.c p2p.h crypto.h gui_helpers.h util.h network.h app.h

gui_page_p2p.o:    gui_page_p2p.c gui_page_p2p.h gui_helpers.h p2p.h util.h app.h

advanced_config.o: advanced_config.c advanced_config.h

gui_page_advanced.o: gui_page_advanced.c gui_page_advanced.h gui_helpers.h advanced_config.h util.h app.h

gui.o:             gui.c gui.h gui_css.h gui_page_share.h gui_page_recv.h gui_page_send.h gui_page_vault.h gui_page_server.h gui_page_p2p.h gui_page_advanced.h server.h p2p.h app.h