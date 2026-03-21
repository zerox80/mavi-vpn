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
   - **Valid redirect URIs**: Enter `http://127.0.0.1:*` and `http://localhost:*` (This allows the Windows CLI to receive the local login callback).
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

The Windows client relies on the QUIC protocol and the WinTUN adapter.

### Prerequisites
* **Rust (Cargo)** installed on your Windows machine.
* `wintun.dll` (Provided in the `windows/` folder or via wintun.net).

### Step-by-Step Guide

**1. Compile the Client:**
Open PowerShell in the root directory:
```powershell
cargo build --release -p windows-vpn
```

**2. Assemble the Files:**
Create a folder (e.g. `C:\MaviVPN\`) and place these three files inside:
* `target\release\mavi-vpn.exe` (The CLI tool)
* `target\release\mavi-vpn-service.exe` (The background service)
* `wintun.dll` (The network driver)

**3. Install the Background Service (Run as Administrator):**
```powershell
cd C:\MaviVPN\
.\mavi-vpn-service.exe install
net start MaviVPNService
```

**4. Connect to the VPN (Normal User):**
```powershell
.\mavi-vpn.exe start
```
The client will interactivly ask for:
* Server Endpoint: `your-server-ip:10433`
* Auth Token: *(From your .env)*
* Certificate PIN: *(From data/cert_pin.txt)*

To disconnect/check status:
```powershell
.\mavi-vpn.exe status
.\mavi-vpn.exe stop
```

### Troubleshooting
If the client fails, check the Windows service logs by running it manually in an admin console:
```powershell
$env:RUST_LOG = "debug"
.\mavi-vpn-service.exe --console
```
