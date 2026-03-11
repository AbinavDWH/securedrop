# ══════════════════════════════════════════════════════════════
# SecureDrop v4.0 — Build System
# ══════════════════════════════════════════════════════════════

CC       = gcc
CFLAGS   = -Wall -Wextra -Wno-unused-parameter -O2 -g \
           $(shell pkg-config --cflags gtk+-3.0) \
           -D_GNU_SOURCE

LDFLAGS  = $(shell pkg-config --libs gtk+-3.0) \
           -lmicrohttpd \
           -lcurl \
           -lssl \
           -lcrypto \
           -lpthread \
           -lm

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
	    sub_tor.c

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
dirs:
	@mkdir -p $(VAULT_DIR) $(STORE_DIR) $(OUTPUT_DIR) \
	          $(META_DIR) $(TOR_DIR) 2>/dev/null || true

# ── Link ───────────────────────────────────────────────────────
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# ── Compile ────────────────────────────────────────────────────
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Stripped release binary ────────────────────────────────────
release: $(TARGET)
	strip -s $(TARGET) -o $(RELEASE)
	@echo ""
	@echo "Release binary: $(RELEASE)"
	@ls -lh $(RELEASE)

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
	rm -f node_pub.pem node_priv.pem

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

main.o:            main.c app.h gui.h tor.h storage.h onion.h

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

gui.o:             gui.c gui.h gui_css.h gui_page_share.h gui_page_recv.h gui_page_send.h gui_page_vault.h gui_page_server.h server.h app.h

protocol.o:        protocol.c protocol.h storage.h crypto.h util.h gui_helpers.h app.h

storage.o:         storage.c storage.h crypto.h util.h gui_helpers.h app.h

server.o:   server.c server.h protocol.h storage.h network.h gui_helpers.h crypto.h util.h onion.h parallel.h sub_tor.h app.h

onion.o:           onion.c onion.h gui_helpers.h util.h app.h

tor_pool.o:        tor_pool.c tor_pool.h gui_helpers.h util.h app.h

parallel.o:        parallel.c parallel.h gui_helpers.h util.h tor.h app.h

client.o:          client.c client.h protocol.h crypto.h gui_helpers.h util.h tor.h parallel.h tor_pool.h app.h

sub_tor.o:  sub_tor.c sub_tor.h gui_helpers.h util.h app.h