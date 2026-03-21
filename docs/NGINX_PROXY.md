# Production Deployment: Nginx Reverse Proxy (Wildcard SSL)

This guide explains how to deploy the Mavi VPN backend (Keycloak + Traefik) behind an existing Nginx server on a Linux host that already manages a wildcard Let's Encrypt certificate.

## 🔗 Architecture Overview
```mermaid
graph LR
    User[User/Client] -- ":443 (HTTPS)" --> Nginx[Nginx (Wildcard SSL)]
    Nginx -- ":11443 (HTTPS/Decrypted)" --> Traefik[Traefik]
    Traefik -- ":8080 (HTTP)" --> Keycloak[Keycloak]
```

## 🛠 1. Backend Configuration (.env)

Set the following variables in your `backend/.env` file on the Linux server:

```bash
# Set Traefik to listen on 11443 for its entrypoint
TRAEFIK_HTTPS_PORT=11443

# Disable Traefik's internal ACME (Nginx handles it)
# Leave empty
TRAEFIK_ACME_RESOLVER=
```

## 📜 2. Nginx Server Configuration

Add this block to your Nginx configuration (e.g., `/etc/nginx/sites-available/mavi-vpn`):

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com; # Replace with your domain

    # Use your existing Wildcard Certificate paths
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        # Proxy to Traefik on port 11443
        proxy_pass https://127.0.0.1:11443;
        
        # Required Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Since Traefik uses a self-signed fallback when ACME is off
        proxy_ssl_verify off;

        # WebSocket support (Required for some Keycloak interactions)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🚀 3. Deployment

### 🔄 Step 0: Syncing the Branch
Since the `beta-keycloak` branch was rebased and force-pushed, a standard `git pull` will fail. Run this on your server:
```bash
git fetch origin beta-keycloak
git reset --hard origin/beta-keycloak
```

### ⚙️ Step 1: Update Configuration
1.  Update `.env` as shown above.
2.  Restart the backend:
    ```bash
    docker-compose down
    docker-compose --profile traefik --profile keycloak up -d
    ```
3.  Reload Nginx:
    ```bash
    nginx -t && systemctl reload nginx
    ```

## 🛠 Troubleshooting

### 1. I still see "Welcome to Nginx"
This means the default Nginx configuration is overriding your custom one.
1.  **Check if enabled**: Ensure your config is in `sites-enabled`:
    ```bash
    ln -s /etc/nginx/sites-available/mavi-vpn /etc/nginx/sites-enabled/
    ```
2.  **Disable default**: Remove the default Nginx site:
    ```bash
    rm /etc/nginx/sites-enabled/default
    ```
3.  **Check Syntax**: Run `nginx -t` to ensure there are no errors.
4.  **Reload**: `systemctl reload nginx`

### 2. Connection Refused / 502 Bad Gateway
- Ensure Traefik is actually running and listening on port **11443**.
- Check `docker ps` to verify the port mapping: `0.0.0.0:11443->443/tcp`.
