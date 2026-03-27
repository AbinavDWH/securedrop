#!/bin/bash

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
# SecureDrop v4.0 — One-command build
# Usage: ./build.sh [release|clean|run]
# ══════════════════════════════════════════════════════════════

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║  SecureDrop v5.0 — Build             ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Check dependencies first ──────────────────────────────────
echo "Checking dependencies..."

MISSING=0

for lib in gtk+-3.0 libmicrohttpd libcurl openssl; do
    if ! pkg-config --exists "$lib" 2>/dev/null; then
        echo -e "  ${RED}[MISSING]${NC} $lib"
        MISSING=1
    fi
done

if ! which gcc > /dev/null 2>&1; then
    echo -e "  ${RED}[MISSING]${NC} gcc"
    MISSING=1
fi

if [ $MISSING -eq 1 ]; then
    echo ""
    echo -e "${RED}Missing dependencies!${NC}"
    echo "Run: ./install_deps.sh"
    exit 1
fi

echo -e "  ${GREEN}All dependencies OK${NC}"
echo ""

# ── Handle arguments ──────────────────────────────────────────
case "${1:-build}" in
    clean)
        echo "Cleaning..."
        make clean
        echo -e "${GREEN}Done.${NC}"
        ;;
    release)
        echo "Building release..."
        make -j$(nproc) release
        echo ""
        echo -e "${GREEN}Release binary ready:${NC}"
        ls -lh securedrop.bin
        ;;
    run)
        echo "Building and running..."
        make -j$(nproc)
        echo ""
        echo -e "${GREEN}Launching SecureDrop...${NC}"
        echo ""
        ./securedrop
        ;;
    build|*)
        echo "Building with $(nproc) cores..."
        make -j$(nproc)
        ;;
esac