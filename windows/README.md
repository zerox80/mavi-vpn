# Mavi VPN - Windows CLI Client

Interaktiver Kommandozeilen-VPN-Client für Windows, basierend auf QUIC mit WinTUN.

## Voraussetzungen

1. **WinTUN Driver**: Lade `wintun.dll` von [wintun.net](https://www.wintun.net/) herunter und platziere sie im selben Verzeichnis wie die Executable.

2. **Administrator-Rechte**: Das Programm muss als Administrator ausgeführt werden.

## Build

```powershell
cargo build --release -p windows-vpn
```

Die Executable befindet sich unter `target/release/mavi-vpn.exe`.

## Verwendung

Starte das Programm:

```powershell
.\mavi-vpn.exe
```

### Erster Start

Beim ersten Start werden alle Daten abgefragt und automatisch gespeichert:

```
╔══════════════════════════════════════╗
║         Mavi VPN - Windows           ║
╚══════════════════════════════════════╝

Server Endpoint (z.B. vpn.example.com:443): vpn.mavi.io:443
Auth Token: mein-geheimes-token
Certificate PIN (SHA256 hex): a1b2c3d4...
Censorship Resistant Mode? [j/N]: n
```

### Weitere Starts

Die gespeicherte Konfiguration wird automatisch erkannt:

```
Gespeicherte Konfiguration gefunden:
  Endpoint: vpn.mavi.io:443
  Token: mein-geh...
  CR Mode: Nein

Diese Konfiguration verwenden? [J/n]: 
```

- **Enter** oder **J** → Gespeicherte Config verwenden
- **N** → Neue Config eingeben

Die Konfiguration wird in `config.json` neben der Executable gespeichert.

## Beenden

Drücke `Ctrl+C` um die Verbindung sauber zu trennen.

## Logging

Setze die Umgebungsvariable `RUST_LOG` für detailliertere Logs:

```powershell
$env:RUST_LOG = "debug"
.\mavi-vpn.exe
```
