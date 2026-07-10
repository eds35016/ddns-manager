# DDNS Manager — Setup Guide

A single service, meant to run on any always-on Linux box on your home network (Raspberry Pi, Orange Pi, an old laptop, a VM — anything that stays powered on), that:

1. **Monitors your public IP** (IPv4 and IPv6) on a schedule you choose.
2. **Updates Cloudflare DNS records** you've flagged for auto-update whenever the IP changes.
3. **Notifies you via Discord and email** (multiple webhooks / recipients supported), including whether each DNS update succeeded — plus a one-time alert if the service itself runs into trouble (IP lookup failing, Cloudflare unreachable) and a notice when it recovers.
4. **Hosts a local web GUI** on your LAN for managing *all* your Cloudflare DNS records (create/edit/delete any type, proxied or not) and for changing every setting live — no service restart needed.

---

## How it works

One Python process, two parts:

- A **poller thread** wakes every *N* seconds (default 300), fetches your public IPv4/IPv6, and — if anything changed — PATCHes each tracked record's content in Cloudflare, then sends one combined summary to Discord and email. The first check after every startup is a **full reconcile**: it compares the actual record contents in Cloudflare against your current IP, so an IP change that happened while the Pi was off is caught immediately.
- A **web server** (Waitress + Flask) serving the GUI on your LAN. Saving settings or toggling a record wakes the poller instantly, which is why changes apply without restarting.

If your Cloudflare token ever becomes invalid, the service **keeps running** — the dashboard shows a persistent error banner, you paste a new token into Settings, and it recovers on the next cycle automatically.

### Files

| File                        | Purpose                                                        |
| --------------------------- | -------------------------------------------------------------- |
| `ddns_service.py`         | Entry point — run this                                        |
| `poller.py`               | IP monitoring, DNS updates, notifications                      |
| `web.py`                  | Flask routes (GUI + JSON API)                                  |
| `cloudflare_client.py`    | Cloudflare API wrapper                                         |
| `config_store.py`         | Config/state persistence (atomic writes)                       |
| `templates/`, `static/` | Web GUI                                                        |
| `config.json`             | **Created on first run.** Settings + secrets (chmod 600) |
| `state.json`              | Created at runtime. Last IP / status for the dashboard         |
| `ddns-manager.service`    | systemd unit                                                   |

### Configuration reference (`config.json`)

You normally never edit this file — everything except the bind address/port is editable in the GUI, and the GUI is the source of truth (hand edits while the service runs get overwritten).

| Key                                          | Meaning                                                                                                    | Default                |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------- |
| `admin_username` / `admin_password_hash` | GUI login (password stored hashed)                                                                         | `admin` / generated  |
| `session_secret`                           | Signs session cookies                                                                                      | generated              |
| `bind_host` / `bind_port`                | Where the GUI listens (restart to change)                                                                  | `0.0.0.0` / `8080` |
| `poll_interval_seconds`                    | IP check interval (60–86400)                                                                              | `300`                |
| `cloudflare_api_token`                     | API token, scope**Zone → DNS → Edit**                                                              | —                     |
| `cloudflare_zone_id`                       | 32-char hex zone ID                                                                                        | —                     |
| `ddns_tracked_record_ids`                  | Record IDs auto-updated with your IP                                                                       | `[]`                 |
| `discord_webhook_urls`                     | List of Discord webhooks — each gets every notification                                                   | `[]`                 |
| `smtp.*`                                   | Email: host, port, security (`starttls`/`ssl`/`none`), username, password, from, `to_addrs` (list) | port 587 starttls      |
| `notifications_enabled`                    | Master switch for both channels                                                                            | `true`               |
| `notify_on_errors`                         | Alert once when IP lookup / Cloudflare access starts failing, and once on recovery                         | `true`               |

---

## Part 1 — Cloudflare setup (do this first, from any machine)

1. **Create a scoped API token** (do *not* use the Global API Key):
   - Cloudflare dashboard → profile icon → **My Profile → API Tokens → Create Token**.
   - Use the **Edit zone DNS** template.
   - Under *Zone Resources*, pick **Include → Specific zone → your domain**.
   - Create it and copy the token — it's shown only once.
2. **Copy your Zone ID**: dashboard → your domain → **Overview** page → right-hand column → *Zone ID* (32 hex characters).
3. That's all — record management itself happens in this app's GUI once it's running.

**Tips for your records** (from the GUI later):

- Give DDNS-tracked records a **TTL of 120–300 s** so clients pick up a new IP quickly.
- **Proxied (orange cloud) records** only carry HTTP/HTTPS. Your web subdomain can stay proxied (this also hides your home IP), but records used for **game servers, Plex, etc.** should be **DNS only (grey cloud)** or the ports simply won't reach you.

## Part 2 — Discord webhook(s)

1. In your Discord server: **Server Settings → Integrations → Webhooks → New Webhook**.
2. Pick the channel that should receive IP-change alerts, copy the **Webhook URL**.
3. Paste it into the GUI's Settings page later. You can add **as many webhooks as you like** (different channels or servers) — every webhook receives each notification.

## Part 3 — Email (SMTP)

From your mailbox provider (domain registrar mail, etc.) you need:

- SMTP **host** (e.g. `mail.yourprovider.com`) and **port** — usually **587 with STARTTLS** or **465 with SSL** (both supported; pick in Settings).
- **Username + password** — if the account has 2FA, create an *app password*.
- A **from** address the account may send as, and one or more **to** addresses (comma-separated in Settings) — all recipients get each alert in a single email.

Notes:

- Home ISPs block outbound port 25 — always use authenticated submission on 587/465.
- Use the GUI's *Check now* button after configuring to trigger a cycle; if your IP just changed you'll get a real test of both channels. (Alerts are only sent when an IP change is detected.)

---

## Part 4 — Deploying on your Linux box

Assumes Debian/Ubuntu (including Raspberry Pi OS and Armbian/Orange Pi images), any architecture. Ubuntu 22.04+/Debian 12+ refuse system-wide `pip install` (PEP 668) — the venv below is required, don't work around it with `--break-system-packages`.

```bash
# 1. Clone the repo directly onto the machine that will run the service
sudo mkdir -p /opt/ddns-manager
sudo git clone https://github.com/eds35016/ddns-manager.git /opt/ddns-manager
cd /opt/ddns-manager

# 2. Create a dedicated non-root user and a virtualenv
sudo useradd --system --home /opt/ddns-manager --shell /usr/sbin/nologin ddns
sudo apt update && sudo apt install -y python3-venv git
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt
sudo chown -R ddns:ddns /opt/ddns-manager

# 3. First run — capture the generated admin password from the output
sudo -u ddns venv/bin/python ddns_service.py
#   -> note the one-time "Username / Password" lines, then Ctrl-C

# 4. Lock down the secrets file
sudo chmod 600 /opt/ddns-manager/config.json

# 5. Install and start the service
sudo cp ddns-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ddns-manager
systemctl status ddns-manager          # should be active (running)
journalctl -u ddns-manager -f          # live logs

# 6. If ufw is enabled, allow the GUI from your LAN only (adjust subnet):
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
```

**Updating later**: `cd /opt/ddns-manager && sudo git pull && sudo venv/bin/pip install -r requirements.txt && sudo systemctl restart ddns-manager`. Your `config.json`/`state.json` aren't tracked by git (see `.gitignore`), so pulling never touches your settings.

Then from any device on your LAN, open **`http://<host-ip>:8080`**, log in, and:

1. **Change the admin password** (Settings → Change admin password). The generated one was printed to the journal, so rotate it right away.
2. Enter the **Cloudflare token + Zone ID**, hit **Test Cloudflare connection**.
3. Add your **Discord webhook(s)** and **SMTP** details, save.
4. Open **DNS Records**, flip the **DDNS toggle** on each A/AAAA record that should follow your home IP.
5. Back on the **Dashboard**, hit **Check now** and watch the records update.

### Don't forget the router

DDNS only keeps your hostnames pointed at the current IP. On your router you still need to **port-forward** each service (game server ports, Plex 32400, web 80/443) to the machine that hosts them, or nothing will be reachable from outside your network.

---

## Security notes

- **Never port-forward the GUI port (8080) on your router.** It's designed for LAN use only.
- The GUI requires login everywhere; sessions expire after 12 h; five failed logins lock that IP out for 5 minutes.
- The admin password is stored only as a hash. `config.json` does hold the Cloudflare token / SMTP password / webhook URL in plaintext (the service needs them to authenticate) — that's why it must stay `chmod 600` and owned by the `ddns` user.
- Traffic between your browser and the Pi is plain HTTP on your LAN — an accepted risk for a single-user home network. If you ever want TLS, put Caddy or nginx in front of it; don't expose it to the internet either way.

## Troubleshooting

| Symptom                                                   | Likely cause / fix                                                                                                        |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Dashboard banner:*Cloudflare authentication failed*     | Token expired/mis-scoped. Create a new**Zone → DNS → Edit** token, paste into Settings — recovers automatically. |
| *Test connection* fails with error 9109/10000           | Token doesn't cover this zone. Check the token's Zone Resources.                                                          |
| Records page:*Couldn't load records* with an error code | The panel shows Cloudflare's own message — usually zone ID typo (must be the 32-char hex ID, not the domain name).       |
| Discord shows`failed: 401/404` on the dashboard         | Webhook was deleted or the URL is truncated. Create a new webhook.                                                        |
| Email`failed: authentication`                           | Wrong username/password, or the provider wants an app password. Also check 587↔STARTTLS vs 465↔SSL pairing.             |
| No IPv6 shown                                             | Normal if your ISP doesn't provide IPv6. AAAA records are skipped gracefully.                                             |
| GUI unreachable from other devices                        | Pi firewall (see ufw step) or`bind_host` was changed from `0.0.0.0`.                                                  |
| Service won't start after editing config.json by hand     | Validate the JSON. Restore from`config.example.json` shape; better, change settings via the GUI.                        |
| Where are the logs?                                       | `journalctl -u ddns-manager -e` — the service logs to stdout; journald keeps and rotates them.                         |
