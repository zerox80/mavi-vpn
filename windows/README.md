# Mavi VPN – Windows

VPN-Client für Windows mit QUIC-Transport und WinTUN. Verfügbar als CLI und grafische Oberfläche (GUI via Tauri). Der Hintergrund-Service übernimmt die eigentliche Tunnelarbeit; CLI und GUI kommunizieren mit ihm über lokales IPC.

---

## Architektur

```
mavi-vpn-client.exe  ──┐
                        ├── IPC (127.0.0.1:14433) ──► mavi-vpn-service.exe
mavi-vpn-gui.exe     ──┘                               (läuft als Windows-Service)
```

Der **Service** muss einmalig als Administrator installiert werden und läuft danach automatisch im Hintergrund. CLI und GUI brauchen danach **keine Admin-Rechte** mehr.

---

## Voraussetzungen

- Windows 10 / 11 (x64)
- Administrator-Rechte für die **einmalige** Service-Installation
- WinTUN ist eingebettet – kein separater Download nötig

---

## Bauen / Building

### CLI + Service

```powershell
cargo build --release -p windows-vpn

# Binaries liegen unter:
# target\release\mavi-vpn-client.exe   ← CLI
# target\release\mavi-vpn-service.exe  ← Hintergrund-Service
```

### GUI (Tauri)

Die GUI braucht das Tauri-CLI-Tool. Es gibt zwei Wege – **Variante A** braucht kein npm:

**Variante A – nur Cargo (empfohlen):**
```powershell
# Einmalig installieren
cargo install tauri-cli

# GUI bauen
cargo tauri build --manifest-path gui/src-tauri/Cargo.toml
```

**Variante B – mit npm/Node.js:**
```powershell
cd gui
npm install
npm run tauri build
```

In beiden Fällen liegt der Installer unter:
```
gui\src-tauri\target\release\bundle\msi\      ← MSI Installer
gui\src-tauri\target\release\bundle\nsis\     ← Setup.exe
gui\src-tauri\target\release\mavi-vpn-gui.exe ← Portable
```

---

## Installation & Setup

### Schritt 1 – Service installieren (einmalig, als Administrator)

```powershell
# PowerShell als Administrator öffnen
.\mavi-vpn-service.exe install

# Service starten
net start MaviVPNService

# Prüfen ob der Service läuft
sc query MaviVPNService
```

Der Service startet ab sofort automatisch mit Windows.

### Schritt 2 – CLI oder GUI starten

Nach der Service-Installation **kein Admin mehr nötig**:

```powershell
# CLI (interaktiv)
.\mavi-vpn-client.exe

# GUI
.\mavi-vpn-gui.exe
```

---

## CLI-Verwendung

### Erster Start

```
╔══════════════════════════════════════╗
║         Mavi VPN - Windows           ║
╚══════════════════════════════════════╝

Server Endpoint (z.B. vpn.example.com:443): vpn.example.com:4433
Nutze Keycloak Authentifizierung? [j/N]: n
Auth Token: dein-geheimes-token
Certificate PIN (SHA256 hex): a1b2c3d4e5f6...
Censorship Resistant Mode? [j/N]: n
```

Die Konfiguration wird automatisch als `config.json` neben der Executable gespeichert.

### Folgestarts

```
Gespeicherte Konfiguration gefunden:
  Endpoint: vpn.example.com:4433
  Token: dein-geh...
  CR Mode: Nein

Diese Konfiguration verwenden? [J/n]:
```

- **Enter** oder **J** → Gespeicherte Config verwenden und verbinden
- **N** → Neue Config eingeben

### CLI-Befehle

```powershell
# Interaktiver Modus (Standard)
.\mavi-vpn-client.exe

# Direkt verbinden (mit gespeicherter Config)
.\mavi-vpn-client.exe start

# Trennen
.\mavi-vpn-client.exe stop

# Status prüfen
.\mavi-vpn-client.exe status
```

---

## GUI-Verwendung

Die GUI verbindet sich automatisch mit dem laufenden Service.

1. **Starten** – `mavi-vpn-gui.exe` doppelklicken
2. **Settings öffnen** – Klick auf „Settings" (beim ersten Start automatisch offen)
3. **Konfigurieren:**
   - Server Endpoint eintragen
   - Auth Token oder Keycloak aktivieren
   - Certificate PIN eingeben
   - „Save Settings" klicken
4. **Verbinden** – „Connect" Button klicken
5. **System Tray** – Die GUI minimiert in den System Tray; Rechtsklick für Connect/Disconnect/Quit

---

## Keycloak SSO

CLI und GUI unterstützen Keycloak-Login per Browser (OAuth2 PKCE):

**CLI:**
```
Nutze Keycloak Authentifizierung? [j/N]: j
Keycloak Server URL: https://auth.example.com
Realm: mavi-vpn
Client ID: mavi-client
→ Browser öffnet sich → Login → Token wird automatisch übernommen
```

**GUI:** Keycloak-Option im Settings-Panel aktivieren, dann auf „Connect" – der Browser öffnet sich automatisch.

---

## Konfiguration

Die CLI speichert `config.json` neben der Executable. Die GUI speichert unter `%APPDATA%\com.mavi.vpn\config.json`.

**Beispiel:**
```json
{
  "endpoint": "vpn.example.com:4433",
  "token": "dein-auth-token",
  "cert_pin": "a1b2c3d4e5f6...",
  "censorship_resistant": false,
  "kc_auth": false
}
```

### Certificate PIN ermitteln

```powershell
# Vom Server-Admin bereitgestellt, oder vom Server-Verzeichnis:
type data\cert_pin.txt
```

---

## Konfiguration des Service

Der Service wird über IPC gesteuert – keine eigene Config-Datei nötig. Die Config wird beim `Start`-Befehl übergeben.

---

## Service-Verwaltung

```powershell
# Status
sc query MaviVPNService

# Manuell starten / stoppen
net start MaviVPNService
net stop MaviVPNService

# Service deinstallieren
net stop MaviVPNService
.\mavi-vpn-service.exe uninstall

# Logs (Event Viewer oder direkt im Console-Modus)
.\mavi-vpn-service.exe --console
```

---

## Features

| Feature | Details |
|---------|---------|
| Transport | QUIC über UDP, BBR Congestion Control |
| TUN-Treiber | WinTUN (eingebettet, kein extra Download) |
| Dual-Stack | IPv4 + IPv6 vollständig unterstützt |
| MTU | 1280 Payload / 1360 Wire (pinned) |
| Certificate Pinning | SHA-256 Fingerabdruck, verhindert MitM |
| Censorship Resistance | H3 ALPN (sieht aus wie HTTP/3) |
| DNS Leak Prevention | NRPT-Regeln + SMHNR deaktiviert |
| Auto-Reconnect | Exponential Backoff (1s → 30s) |
| Keycloak SSO | OAuth2 PKCE, öffnet Browser automatisch |
| GUI | Tauri (WebView2), System Tray, Dark Theme |
| Service | Windows Service (Auto-Start, kein Admin für CLI/GUI nötig) |

---

## Debugging

```powershell
# Detaillierte Logs im Console-Modus
$env:RUST_LOG = "debug"
.\mavi-vpn-service.exe --console

# Routing prüfen
route print

# DNS prüfen
ipconfig /all
Get-DnsClientNrptRule

# TUN-Interface
Get-NetAdapter | Where-Object { $_.Name -like "MaviVPN*" }
```

---

## Deinstallation

```powershell
# Als Administrator
net stop MaviVPNService
.\mavi-vpn-service.exe uninstall

# Dateien löschen (optional)
Remove-Item -Recurse "$env:APPDATA\com.mavi.vpn"
```
