# SentinelSSH — Production Deployment

Deploy the honeypot + SOC dashboard to an **Ubuntu 24.04 LTS** VPS (Hetzner or
DigitalOcean) behind Nginx with HTTPS. The stack runs via Docker Compose and is
supervised by systemd.

> **Architecture in production**
> `Internet :22` → **honeypot container** (real attacker SSH)
> `Internet :443` → **Nginx** → **backend container :8008** (dashboard/API + WebSocket)
> Your real admin SSH is moved to a non-standard port so the honeypot can own 22.

---

## 0. Prerequisites

- A registered domain (e.g. `soc.example.com`).
- An SSH keypair on your workstation (`ssh-keygen -t ed25519`).
- A VPS provider account (Hetzner or DigitalOcean).

---

## 1. Provision the VPS

### Hetzner Cloud
1. **Project → Add Server**.
2. Location: any. Image: **Ubuntu 24.04**.
3. Type: **CX22** (2 vCPU / 4 GB) is plenty for the demo.
4. **SSH keys**: add your public key.
5. (Optional) Enable **Backups** (+20%) for provider-level snapshots.
6. Create → note the public IPv4.

### DigitalOcean
1. **Create → Droplets**.
2. Region: nearest. Image: **Ubuntu 24.04 (LTS) x64**.
3. Plan: **Basic / Regular, 2 GB–4 GB**.
4. Authentication: **SSH Key** (add yours).
5. (Optional) Enable **Backups**.
6. Create → note the public IPv4.

---

## 2. DNS / Domain configuration

At your DNS provider create an **A record**:

| Type | Name              | Value (VPS IPv4) | TTL  |
|------|-------------------|------------------|------|
| A    | `soc`             | `<VPS_IP>`       | 3600 |
| AAAA | `soc` (if IPv6)   | `<VPS_IPv6>`     | 3600 |

Verify before requesting certificates:
```bash
dig +short soc.example.com
```

---

## 3. Initial server hardening (run as root, then switch to a user)

```bash
ssh root@<VPS_IP>

# Create an admin user with sudo + your key
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy

# Patch
apt update && apt -y upgrade
```

### Move real SSH off port 22 (honeypot will take 22)
```bash
sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
```
> **Keep your current session open.** In a new terminal confirm key login works
> on the new port before closing: `ssh -p 2200 deploy@<VPS_IP>`.

---

## 4. UFW firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow 2200/tcp comment 'admin SSH'
sudo ufw allow 80/tcp    comment 'HTTP (ACME redirect)'
sudo ufw allow 443/tcp   comment 'HTTPS dashboard'
sudo ufw allow 22/tcp    comment 'honeypot SSH (intentional)'

sudo ufw enable
sudo ufw status numbered
```
> Port `8008` is **not** exposed publicly — Nginx reaches it over localhost only.

---

## 5. Install Docker Engine + Compose plugin

```bash
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker deploy   # log out/in for group to apply
```

---

## 6. Deploy the application

```bash
sudo mkdir -p /opt/sentinelssh && sudo chown deploy:deploy /opt/sentinelssh
git clone <your-repo-url> /opt/sentinelssh
cd /opt/sentinelssh

cp .env.docker.example .env
```

Edit `.env` and **change every secret**:
```ini
POSTGRES_PASSWORD=<long-random>
SECRET_KEY=<openssl rand -hex 32>
INTERNAL_API_TOKEN=<openssl rand -hex 32>
ADMIN_USERNAME=<your-admin>
ADMIN_PASSWORD=<strong-password>
SESSION_COOKIE_SECURE=true          # served over HTTPS
CORS_ORIGINS=https://soc.example.com
DEMO_MODE=false                      # production: fill from real attacks
HONEYPOT_PUBLISH_PORT=22             # honeypot owns the real SSH port
```

Generate secrets quickly:
```bash
openssl rand -hex 32
```

First boot:
```bash
docker compose up -d --build
docker compose ps
docker compose logs -f backend     # watch for "starting backend on :8008"
```

---

## 7. Systemd service (start on boot)

```bash
sudo cp deploy/systemd/sentinelssh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelssh

systemctl status sentinelssh
```
Manage:
```bash
sudo systemctl restart sentinelssh   # redeploy/restart
sudo systemctl stop sentinelssh
```

---

## 8. Nginx reverse proxy + HTTPS (Let's Encrypt)

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx

# Install the site config (edit server_name to your domain first)
sudo cp deploy/nginx/sentinelssh.conf /etc/nginx/sites-available/sentinelssh
sudo sed -i 's/soc.example.com/soc.YOURDOMAIN.com/g' /etc/nginx/sites-available/sentinelssh
sudo ln -s /etc/nginx/sites-available/sentinelssh /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

sudo nginx -t && sudo systemctl reload nginx

# Obtain + install the certificate (auto-edits the config)
sudo certbot --nginx -d soc.YOURDOMAIN.com --redirect --agree-tos -m you@email.com --no-eff-email
```

Certbot installs a renewal timer. Verify:
```bash
sudo systemctl status certbot.timer
sudo certbot renew --dry-run
```

Visit **https://soc.YOURDOMAIN.com** and log in with your admin credentials.

---

## 9. Docker deployment workflow (updates)

```bash
cd /opt/sentinelssh
git pull
docker compose up -d --build       # rebuild changed services, zero data loss
docker compose logs -f backend

# Or via systemd (equivalent):
sudo systemctl restart sentinelssh

# Housekeeping
docker image prune -f
```

Data persists in named volumes (`pgdata`, `honeypot-keys`, `honeypot-data`)
across rebuilds. To wipe everything: `docker compose down -v` (destructive).

---

## 10. Backup strategy

**Layers**
1. **Provider snapshots** — enable Hetzner/DO automated backups (whole-disk DR).
2. **Database dumps** — `deploy/backup.sh` (logical, portable, daily).
3. **Config** — keep `.env` in a password manager / private secrets store
   (never commit it).

Set up daily DB backups:
```bash
chmod +x deploy/backup.sh
( crontab -l 2>/dev/null; echo "30 3 * * * cd /opt/sentinelssh && ./deploy/backup.sh >> /var/log/sentinelssh-backup.log 2>&1" ) | crontab -
```

Restore:
```bash
gunzip -c backups/sentinelssh-YYYYMMDD-HHMMSS.sql.gz | \
  docker compose exec -T db psql -U sentinel -d sentinelssh
```

For off-site retention, sync `backups/` to object storage (e.g. `rclone` to S3 /
DO Spaces / Hetzner Storage Box).

---

## 11. Security hardening checklist

- [ ] Real admin SSH moved to a non-standard port (`2200`), root login disabled, password auth disabled.
- [ ] UFW enabled — only `2200`, `80`, `443`, and honeypot `22` open; `8008` not public.
- [ ] All `.env` secrets randomized (`POSTGRES_PASSWORD`, `SECRET_KEY`, `INTERNAL_API_TOKEN`, admin password).
- [ ] `SESSION_COOKIE_SECURE=true` and `CORS_ORIGINS` pinned to your domain.
- [ ] HTTPS enforced (HTTP→HTTPS redirect) with auto-renewing Let's Encrypt cert + HSTS header.
- [ ] `/api/internal/` blocked at Nginx; honeypot→backend events stay on the internal Docker network.
- [ ] Postgres port (`5432`) never published to the host — internal network only.
- [ ] `DEMO_MODE=false` in production so the dashboard reflects real telemetry.
- [ ] `unattended-upgrades` enabled: `sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`.
- [ ] Fail2ban protecting the **real** admin SSH port: `sudo apt-get install -y fail2ban` (do not jail port 22 — that's the honeypot).
- [ ] Daily DB backups scheduled and a restore test performed.
- [ ] Docker images rebuilt regularly (`git pull && docker compose up -d --build`) to pick up base-image patches.
- [ ] Dashboard admin credentials stored in a password manager; rotate periodically.

---

## 12. Troubleshooting

| Symptom | Check |
|---|---|
| 502 from Nginx | `docker compose ps` / `docker compose logs backend`; is `:8008` healthy? |
| WebSocket not connecting | Confirm `/socket.io/` block in Nginx and `X-Forwarded-Proto`. |
| Can't reach dashboard | `sudo ufw status`; DNS A record; `sudo nginx -t`. |
| No attacks recorded | Confirm `HONEYPOT_PUBLISH_PORT=22` and UFW allows `22`. |
| DB connection errors on boot | Backend waits 60×2s for `db`; check `docker compose logs db`. |
| Cert renewal fails | `sudo certbot renew --dry-run`; port 80 reachable for ACME. |
