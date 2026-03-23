# Mavi VPN – Linux

High-performance VPN client for Linux using QUIC transport. Supports dual-stack (IPv4/IPv6), certificate pinning, censorship resistance, Keycloak SSO, and both CLI and GUI operation.

---

## Voraussetzungen / Requirements

- Linux Kernel 2.6.27+ (TUN/TAP support – practically any modern distro)
- Root-Rechte (für TUN-Device und Routing)
- `iproute2` Paket (stellt `ip` Befehl bereit)

**Fedora/RHEL:**
```bash
sudo dnf install iproute
```

**Debian/Ubuntu:**
```bash
sudo apt install iproute2
```

---

## Bauen / Building

```bash
# Im Projekt-Root
cargo build --release -p linux-vpn

# Binary liegt unter:
target/release/mavi-vpn

# Optional: In PATH installieren
sudo install -m 755 target/release/mavi-vpn /usr/local/bin/mavi-vpn
```

---

## Betriebsmodi / Operation Modes

Es gibt zwei Modi – beide nutzen dieselbe Config-Datei.

### Modus 1: Direkt (CLI, kein Daemon)

Ideal für einfache Nutzung oder Scripting. Die VPN-Verbindung läuft im Vordergrund und endet mit Ctrl+C.

```bash
# Interaktiv (fragt bei erstem Start nach Config)
sudo mavi-vpn

# Mit expliziter Config-Datei
sudo mavi-vpn connect -c /etc/mavi-vpn/mavi-vpn.json

# Status prüfen
mavi-vpn status
```

### Modus 2: Daemon (für GUI oder Hintergrund-Betrieb)

Der Daemon läuft als Root im Hintergrund und nimmt Befehle über einen lokalen IPC-Port (`127.0.0.1:14433`) entgegen. Die GUI nutzt diesen Modus automatisch.

```bash
# Daemon manuell starten
sudo mavi-vpn daemon

# Daemon im Hintergrund starten
sudo mavi-vpn daemon &

# Verbinden (ohne Root, da Daemon die Arbeit übernimmt)
mavi-vpn start
mavi-vpn start -c /etc/mavi-vpn/mavi-vpn.json

# Trennen
mavi-vpn stop

# Status
mavi-vpn status
```

---

## Daemon als systemd-Service (empfohlen für GUI-Nutzung)

1. Binary installieren:
```bash
sudo install -m 755 target/release/mavi-vpn /usr/local/bin/mavi-vpn
```

2. Service-Datei kopieren:
```bash
sudo cp linux/mavi-vpn.service /etc/systemd/system/
sudo systemctl daemon-reload
```

3. Service aktivieren und starten:
```bash
sudo systemctl enable mavi-vpn
sudo systemctl start mavi-vpn
```

4. Status prüfen:
```bash
systemctl status mavi-vpn
journalctl -u mavi-vpn -f
```

Sobald der Service läuft, kann die GUI oder CLI ohne `sudo` Verbindungen aufbauen und trennen.

---

## GUI

Die grafische Oberfläche (Tauri) kommuniziert über den Daemon. Erst den Daemon starten (s.o.), dann die GUI öffnen.

```bash
# Daemon starten (einmalig, oder via systemd)
sudo mavi-vpn daemon &

# GUI starten (kein root nötig)
mavi-vpn-gui
```

Beim ersten Start öffnet die GUI automatisch das Settings-Panel zum Einrichten.

---

## Konfiguration

Die Config wird automatisch an folgendem Ort gespeichert (erste gefundene Datei wird genutzt):

| Priorität | Pfad |
|-----------|------|
| 1 | `$XDG_CONFIG_HOME/mavi-vpn/mavi-vpn.json` |
| 2 | `~/.config/mavi-vpn/mavi-vpn.json` |
| 3 | `/etc/mavi-vpn/mavi-vpn.json` |
| 4 | `./mavi-vpn.json` |

Berechtigungen werden automatisch auf `600` gesetzt (nur Eigentümer kann lesen).

**Beispiel-Config (`mavi-vpn.json`):**
```json
{
  "endpoint": "vpn.example.com:4433",
  "token": "dein-auth-token",
  "cert_pin": "a1b2c3d4e5f6...",
  "censorship_resistant": false,
  "kc_auth": false,
  "kc_url": null,
  "kc_realm": null,
  "kc_client_id": null
}
```

### Certificate PIN ermitteln

Den SHA-256-Fingerabdruck des Server-Zertifikats bekommst du vom Server-Admin, oder:
```bash
# Vom laufenden Server (Datei cert_pin.txt wird beim ersten Start generiert)
cat /path/to/server/data/cert_pin.txt
```

---

## Keycloak SSO

Beim ersten Start mit Keycloak-Option öffnet sich automatisch der Browser (`xdg-open`):

```bash
sudo mavi-vpn
# → "Use Keycloak authentication? [y/N]: y"
# → Browser öffnet sich → Login → Token wird automatisch übernommen
```

Auf **Wayland/Fedora** wird `xdg-open` direkt aufgerufen – funktioniert mit GNOME, KDE, etc.

---

## Features

| Feature | Details |
|---------|---------|
| Transport | QUIC über UDP, BBR Congestion Control |
| Dual-Stack | IPv4 + IPv6 vollständig unterstützt |
| MTU | 1280 Payload / 1360 Wire (pinned) |
| Certificate Pinning | SHA-256 Fingerabdruck, verhindert MitM |
| Censorship Resistance | H3 ALPN (sieht aus wie HTTP/3) |
| DNS Leak Prevention | systemd-resolved oder /etc/resolv.conf |
| Routing | Split-Routes (0/1 + 128/1), kein Default-Route-Überschreiben |
| Auto-Reconnect | Exponential Backoff (1s → 30s) |
| Keycloak SSO | OAuth2 PKCE, öffnet Browser via xdg-open |
| Graceful Shutdown | Routen/DNS werden bei SIGINT/SIGTERM sauber entfernt |

---

## Debugging

```bash
# Detaillierte Logs
RUST_LOG=debug sudo mavi-vpn

# Nur VPN-Core Logs
RUST_LOG=linux_vpn=debug sudo mavi-vpn

# TUN-Interface live beobachten
ip addr show mavi0
ip route show

# DNS prüfen (systemd-resolved)
resolvectl status
```

---

## Deinstallation

```bash
# Service stoppen und entfernen
sudo systemctl stop mavi-vpn
sudo systemctl disable mavi-vpn
sudo rm /etc/systemd/system/mavi-vpn.service
sudo systemctl daemon-reload

# Binary entfernen
sudo rm /usr/local/bin/mavi-vpn

# Config entfernen (optional)
rm -rf ~/.config/mavi-vpn
sudo rm -rf /etc/mavi-vpn
```
