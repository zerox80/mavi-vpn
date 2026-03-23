# Mavi VPN - Ultimate Installation Guide

This guide describes how to deploy the Mavi VPN server and connect clients. The system is designed to be highly modular: you can run just the simple VPN, or deploy the full "Enterprise" stack with Keycloak OIDC authentication and Traefik routing.

---

## 1. Server Installation (Docker Compose)

The backend is fully dockerized for Linux servers.

### Prerequisites
* **Docker** and **Docker Compose** installed.
* Ports open in your firewall:
  * `10433/UDP` (For the VPN tunnel)
  * `80/TCP` & `443/TCP` (If using standalone Traefik)

### Step 1: Prepare the Configuration
Clone the repository and prepare the environment file:
```bash
cd mavi-vpn/backend
cp .env.example .env
nano .env
```

### Step 2: The Critical `.env` Settings
Depending on your needs, configure the `.env` file exactly as follows:

**1. Basic Settings (Required for all modes)**
* `VPN_AUTH_TOKEN`: A secure, long password.
* `VPN_PORT`: e.g. `10433`.

**2. Enterprise Mode (Keycloak + Traefik)**
If you want the web-based Admin UI and user management, you **must** configure these four variables to avoid startup errors:
* `DOMAIN_NAME=yourdomain.com` *(Crucial! Traefik uses this to build routes like `auth.yourdomain.com`)*
* `COMPOSE_FILE=docker-compose.yml:keycloak/docker-compose.yml` *(Uncomment this to load Keycloak)*
* `COMPOSE_PROFILES=traefik,keycloak` *(Crucial! Instructs Docker to actually start these services)*

**3. SSL Routing Strategies**
Choose **one** of the following strategies if you enabled the Enterprise Mode:

▶ **Option A: Standalone (Traefik handles SSL)**
Use this if no other web server is running on your host.
* `TRAEFIK_HTTP_PORT=80`
* `TRAEFIK_HTTPS_PORT=443`
* `TRAEFIK_ACME_RESOLVER=myresolver` (Fetches free Let's Encrypt certificates).

▶ **Option B: Behind Nginx (You already have Wildcard SSL)**
Use this if you already run Nginx/Apache on Port 443.
* `TRAEFIK_HTTP_PORT=11443` (Traefik runs internally on this port).
* `TRAEFIK_HTTPS_PORT=11444` (Dummy port to prevent conflicts).
* `TRAEFIK_ACME_RESOLVER=` (Leave empty! Traefik internal SSL is disabled).
* Check out [`docs/NGINX_PROXY.md`](NGINX_PROXY.md) for the exact Nginx `location /` configuration to proxy traffic to port 11443.

**4. Performance Tuning (Critical for High-Speed)**
* `VPN_MTU=1280`: **(Default)** This sets the TUN adapter payload size. Do not change this unless you know what you're doing. 1280 ensures the final QUIC packets (including headers) stay within 1360-1400 bytes, which is compatible with most mobile and residential networks.
* **Socket Buffers**: The system now automatically requests **4MB** of OS-level UDP buffer space on both the server and client to prevent packet loss during high-speed bursts (GSO).

### Step 3: Start the Server

```bash
docker-compose down
docker-compose up -d --build --force-recreate
```

> **⏳ Important:** Keycloak is a large Java application. Once you run the command above, give the server **1 to 2 minutes** to initialize the database and UI. If you access `auth.yourdomain.com` too early, you will see a `502 Bad Gateway` error. Just wait and refresh!

### Step 4: Configure Keycloak (Enterprise Mode Only)
If you enabled Keycloak, it starts completely empty. You must create the Realm and Client before connecting:
1. Open your browser and navigate to `https://auth.yourdomain.com/`.
2. Click **Administration Console** and log in (Default: `admin` / `admin`).
3. In the top-left dropdown (under the Keycloak logo), click **Create Realm**.
   - Name it exactly: **`mavi-vpn`** and click Create.
4. On the left menu, click **Clients** -> **Create client**.
   - **Client ID**: `mavi-client`
   - Click Next.
   - **Client authentication**: `Off` (We use a Public Client with PKCE).
   - **Standard flow**: `On` (Required for browser-based login).
   - Click Next.
   - **Valid redirect URIs**: Enter these three lines:
     1. `http://127.0.0.1:18923/callback` (For Windows/Linux CLI and GUI)
     2. `mavivpn://oauth` (For Android App)
   - Click Save.
5. On the left menu, click **Users** -> **Add user**.
   - Create a user for yourself.
   - Go to the **Credentials** tab and set a password for this user (turn off "Temporary").

### Step 5: Retrieve the Certificate PIN
For the VPN client to connect securely via QUIC without MITM attacks, you need the server's unique Certificate PIN:
```bash
cat data/cert_pin.txt
```
---

## 2. Windows Client Installation

### Prerequisites
* **Rust (Cargo)** — https://rustup.rs
* **Python 3** (for the install scripts)
* **Administrator privileges** (for the Windows Service)

### Option A: Automated Install (Recommended)

Open **PowerShell as Administrator** in the project root:

```powershell
# 1. Install CLI + Windows Service
python install_cli_windows.py

# 2. Install Tauri GUI (optional)
python install_gui_windows.py
```

The scripts handle everything: building, installing to `C:\Program Files\MaviVPN`, registering and starting the Windows Service, PATH setup, and Desktop shortcuts.

### Option B: Manual Build

```powershell
# Build CLI + Service
cargo build --release -p windows-vpn

# Install service (Administrator required)
.\target\release\mavi-vpn-service.exe install
net start MaviVPNService

# Build GUI (requires cargo-tauri)
cargo install tauri-cli
cd gui && cargo tauri build
```

### Usage

**GUI:** Launch "Mavi VPN" from the Start Menu or Desktop shortcut. Configure endpoint, certificate PIN, and optionally Keycloak in Settings. Click Connect.

**CLI:**
```powershell
mavi-vpn-client start     # Connect (prompts for config on first run)
mavi-vpn-client stop      # Disconnect
mavi-vpn-client status    # Check connection status
```

### Troubleshooting
Run the service in console mode to see debug logs:
```powershell
$env:RUST_LOG = "debug"
.\mavi-vpn-service.exe --console
```

---

## 3. Linux Client Installation

### Prerequisites
* **Rust (Cargo)** — https://rustup.rs
* **Python 3** (for the install scripts)
* **root/sudo** (for TUN device and routing)

### Option A: Automated Install (Recommended)

```bash
# 1. Install CLI + optional systemd service
python3 install_cli_linux.py

# 2. Install Tauri GUI (optional)
python3 install_gui_linux.py
```

The GUI installer auto-detects your distro and installs via RPM (Fedora/RHEL), DEB (Debian/Ubuntu), AppImage, or raw binary fallback.

### Option B: Manual Build

```bash
# Build CLI
cargo build --release -p linux-vpn

# Install binary
sudo install -m 755 target/release/mavi-vpn /usr/local/bin/

# Install systemd service (optional)
sudo cp linux/mavi-vpn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mavi-vpn
```

### Usage

**Direct mode** (no daemon, runs in foreground):
```bash
sudo mavi-vpn                          # Interactive config prompt
sudo mavi-vpn -c /path/to/config.json  # With config file
```

**Daemon mode** (for GUI and remote CLI control):
```bash
sudo mavi-vpn daemon &    # or: sudo systemctl start mavi-vpn
mavi-vpn start            # Connect via daemon
mavi-vpn stop             # Disconnect
mavi-vpn status           # Check connection status
mavi-vpn-gui              # Launch GUI
```

### Config File Location
The CLI searches in order: `./config.json` → `~/.config/mavi-vpn/config.json` → `/etc/mavi-vpn/config.json`

### Troubleshooting
```bash
RUST_LOG=debug sudo mavi-vpn           # Debug direct mode
sudo journalctl -u mavi-vpn -f         # Debug systemd daemon
```

---

## 4. Android Client Installation

The Android client is built as a native Kotlin app with a bundled Rust core for the VPN logic.

### Prerequisites
* **Android Studio** (Koala or newer).
* **Android SDK 36** (target).
* **Rust** with `cargo-ndk` installed:
  ```bash
  cargo install cargo-ndk
  rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
  ```

### Step-by-Step Guide

**1. Configure the Backend:**
Ensure your Keycloak client is configured with the `mavivpn://oauth` redirect URI as described in Section 1, Step 4.

**2. Build the App:**
1. Open the `/android` folder in Android Studio.
2. The project will automatically sync and build the Rust core (via `cargoBuild` task in `build.gradle.kts`).
3. Build the APK via **Build -> Build Bundle(s) / APK(s) -> Build APK(s)**.

**3. Run and Login:**
1. Install the APK on your Android device.
2. Open **MAVI VPN**.
3. Use the **"Login with Keycloak"** button.
4. If it's your first time, click **"Edit Keycloak Server"** to enter your server URL and realm.
5. After login, you'll be redirected back to the app with your token automatically filled.
6. Enter your **Server Endpoint** and **Certificate PIN**.
7. Click **CONNECT**.

**4. Split Tunneling:**
Go to **Settings** (Gear icon) to select which apps should bypass the VPN (Exclude mode) or which apps alone should use it (Include mode).
