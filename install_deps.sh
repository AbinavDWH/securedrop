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
# SecureDrop v4.0 — Dependency Installer
# Supports: Debian, Ubuntu, Mint, Pop!_OS
# ══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║  SecureDrop v5.0 — Setup             ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect package manager ─────────────────────────────────────
if command -v apt-get &> /dev/null; then
    PKG_MGR="apt"
elif command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MGR="pacman"
else
    echo -e "${RED}Unsupported package manager${NC}"
    echo "Install manually:"
    echo "  gtk3-devel libmicrohttpd-devel"
    echo "  libcurl-devel openssl-devel tor"
    exit 1
fi

echo -e "${YELLOW}Package manager: ${PKG_MGR}${NC}"
echo ""

# ── Install ────────────────────────────────────────────────────
case $PKG_MGR in
    apt)
        echo -e "${GREEN}Installing Debian/Ubuntu packages...${NC}"
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            pkg-config \
            libgtk-3-dev \
            libmicrohttpd-dev \
            libcurl4-openssl-dev \
            libssl-dev \
            tor
        ;;
    dnf)
        echo -e "${GREEN}Installing Fedora/RHEL packages...${NC}"
        sudo dnf install -y \
            gcc make pkg-config \
            gtk3-devel \
            libmicrohttpd-devel \
            libcurl-devel \
            openssl-devel \
            tor
        ;;
    pacman)
        echo -e "${GREEN}Installing Arch packages...${NC}"
        sudo pacman -Syu --noconfirm \
            base-devel \
            pkg-config \
            gtk3 \
            libmicrohttpd \
            curl \
            openssl \
            tor
        ;;
esac

echo ""

# ── Verify ─────────────────────────────────────────────────────
echo -e "${CYAN}Verifying installation...${NC}"

PASS=0
FAIL=0

check() {
    if pkg-config --exists "$1" 2>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $1"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[MISSING]${NC} $1"
        FAIL=$((FAIL+1))
    fi
}

check gtk+-3.0
check libmicrohttpd
check libcurl
check openssl

if which tor > /dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC} tor binary"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}[MISSING]${NC} tor binary"
    FAIL=$((FAIL+1))
fi

if which gcc > /dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC} gcc compiler"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}[MISSING]${NC} gcc compiler"
    FAIL=$((FAIL+1))
fi

echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All $PASS dependencies installed!${NC}"
    echo ""
    echo -e "${CYAN}Build steps:${NC}"
    echo "  make              # build"
    echo "  make run          # build and run"
    echo "  make release      # stripped binary"
    echo ""
else
    echo -e "${RED}$FAIL dependency(ies) missing${NC}"
    echo "Fix the missing packages and try again."
    exit 1
fi