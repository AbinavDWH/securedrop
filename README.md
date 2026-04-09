# Veil-Xfer

**Encrypted file sharing over Tor hidden services.**

Veil-Xfer is a privacy-focused file transfer application that enables anonymous, end-to-end encrypted file sharing through the Tor network. Built with a GTK3 graphical interface, it provides multiple transfer modes — server hosting, direct send, peer-to-peer — all routed through Tor onion services for maximum anonymity.


---

## Features

### Military-Grade Encryption
- **AES-256-GCM** chunk-level encryption
- **RSA-4096** key wrapping
- **HKDF-SHA256** key derivation
- **PBKDF2** (1M iterations) password protection

### Tor Integration
- Automatic Tor hidden service creation
- Multi-circuit rotation for traffic analysis resistance
- Per-sub-server independent onion addresses
- Configurable Tor SOCKS proxy support

### Multiple Transfer Modes
| Mode | Description |
|------|-------------|
| **Share** | Host files on an onion server for others to download |
| **Receive** | Download files from a remote Veil-Xfer server |
| **Send** | Push a file directly to a remote server |
| **P2P** | Peer-to-peer transfer with no central server |
| **Server** | Full server mode with distributed chunk storage |

### Distributed & Parallel
- Up to **128 independent sub-servers** for parallel chunk transfer
- Round-robin chunk distribution across sub-servers
- Each sub-server runs its own Tor hidden service
- Configurable chunks-per-sub-server (2 or 4)

### Secure Vault
- Local encrypted file vault
- Password-protected storage with PBKDF2 key derivation
- Import/export encrypted files

### Zero Trust Architecture
- Rate-limited access (lockout after 5 failed attempts)
- Stack protector, PIE, RELRO, non-executable stack
- Hardened build flags by default

---

## Quick Start

### Prerequisites

- **OS**: Linux (Debian/Ubuntu, Fedora, Arch)
- **Tor**: Must be installed and available in `$PATH`
- **GCC**: C compiler with C11 support

### Install Dependencies

```bash
# Automatic (detects apt, dnf, or pacman)
./install_deps.sh

# Or manually on Debian/Ubuntu
sudo apt install build-essential pkg-config libgtk-3-dev \
    libmicrohttpd-dev libcurl4-openssl-dev libssl-dev tor
```

### Build & Run

```bash
# Build
make -j$(nproc)

# Build and run
make run

# Or use the build script
./build.sh run
```

### Release Binary

```bash
make release
# Output: Veil-Xfer.bin (stripped, hardened)
```

---

## Build Targets

| Target | Description |
|--------|-------------|
| `make` | Build the application |
| `make run` | Build and launch |
| `make release` | Stripped + hardened binary |
| `make check` | Verify all dependencies |
| `make install-deps` | Install dependencies (apt) |
| `make clean` | Remove build artifacts |
| `make distclean` | Remove build + data directories |
| `make purge` | Remove everything |

---

## Project Structure

```
Veil-Xfer/
├── main.c                  # Entry point, initialization, cleanup
├── app.h                   # Global state, constants, data structures
├── gui.c/h                 # Main GTK3 window, sidebar, navigation
├── gui_css.c/h             # CSS styling for dark theme
├── gui_helpers.c/h         # Logging, progress, UI utilities
├── gui_page_share.c/h      # Share mode page
├── gui_page_recv.c/h       # Receive mode page
├── gui_page_send.c/h       # Send mode page
├── gui_page_vault.c/h      # Secure vault page
├── gui_page_server.c/h     # Server mode page
├── gui_page_p2p.c/h        # P2P mode page
├── gui_page_advanced.c/h   # Advanced configuration page
├── server.c/h              # HTTP server (libmicrohttpd)
├── client.c/h              # HTTP client (libcurl)
├── protocol.c/h            # Upload/download protocol handling
├── storage.c/h             # Chunk storage, sub-server management
├── crypto.c/h              # AES-GCM, RSA, HKDF, PBKDF2
├── tor.c/h                 # Tor circuit detection and management
├── onion.c/h               # Tor hidden service lifecycle
├── tor_pool.c/h            # Tor instance pool management
├── sub_tor.c/h             # Per-sub-server Tor instances
├── p2p.c/h                 # Peer-to-peer transfer engine
├── parallel.c/h            # Parallel chunk upload/download
├── network.c/h             # Low-level network utilities
├── filelist.c/h            # File listing and metadata
├── util.c/h                # General utilities
├── advanced_config.c/h     # Persistent advanced settings
├── Makefile                # Build system
├── build.sh                # One-command build script
├── install_deps.sh         # Dependency installer
└── LICENSE                 # GNU GPL v3
```

---

## Security Hardening

The build system enables the following protections by default:

- **Stack Protector** (`-fstack-protector-strong`)
- **Position Independent Executable** (`-fPIE` / `-pie`)
- **FORTIFY_SOURCE** level 2
- **Full RELRO** (`-Wl,-z,relro,-z,now`)
- **Non-executable stack** (`-Wl,-z,noexecstack`)
- **Stack clash protection** (`-fstack-clash-protection`)
- **Control flow protection** (`-fcf-protection`)

Verify with:
```bash
make release
# Prints security check results
```

---

## Configuration

### Advanced Settings

The Advanced page in the GUI allows tuning:

- **Chunks per sub-server**: 2 or 4
- **Retry timeout**: Connection retry delay (ms)
- **Max retries**: Number of retry attempts
- **Thread count**: Parallel transfer threads
- **Warmup stagger**: Delay between sub-server launches (ms)

Settings persist across sessions in the configuration file.

### Network Defaults

| Parameter | Default |
|-----------|---------|
| Main server port | `8443` |
| Sub-server port range | `10000–10127` |
| Max sub-servers | `128` |
| P2P default port | `9900` |
| Onion virtual port | `80` |
| Onion bootstrap timeout | `120s` |

---

## License

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License v3.0** as published by the Free Software Foundation.

See [LICENSE](LICENSE) for the full license text.

---

## Author

**Abinav** — 2026

---

> **Disclaimer**: This software is provided for legitimate privacy and security use cases. Users are responsible for complying with applicable laws in their jurisdiction.
