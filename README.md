# DDNS Manager

A self-hosted DDNS client **and** full Cloudflare DNS manager, wrapped in a single small Python service with a polished local web GUI. Built for home servers (game servers, Plex, self-hosted web apps) sitting behind a residential connection without a static IP.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What it does

- **Watches your public IPv4/IPv6** on a schedule you choose (default every 5 minutes, live-adjustable) and keeps the Cloudflare DNS records you flag in sync with it.
- **Manages your entire Cloudflare zone** from the browser — create, edit, and delete any record type (A, AAAA, CNAME, TXT, MX, SRV, CAA, and others via a raw-JSON fallback), proxied or not — so you rarely need to open the Cloudflare dashboard.
- **Notifies you** via any number of Discord webhooks and email recipients whenever your IP changes, including whether each DNS update actually succeeded — plus a one-time alert (and a recovery notice) if the service itself runs into trouble, e.g. IP lookup failing or Cloudflare being unreachable.
- **Applies every setting live.** Poll interval, credentials, tracked records, notification targets — all editable from Settings with no service restart.
- Ships as **one systemd service**: a background poller thread plus a Flask + Waitress web server in a single process.

## Why this exists

Most DDNS clients are single-purpose CLI tools that only touch one record and offer no visibility into whether an update worked. This project started from wanting that reliability (dual notifications, success/failure reporting, auto-recovery from a bad token) plus a real DNS management UI, so a Raspberry Pi/Orange Pi/old laptop on the LAN can be the one place you manage your domain — not the Cloudflare dashboard, and not a fragile bash script in a cron job.

## Screenshots

_Dashboard, DNS record manager, and settings pages — run it locally (see below) to see the current look; both light and dark themes are supported._

## Requirements

- Python 3.9+
- A domain on Cloudflare (free tier is fine) and an API token scoped to **Zone → DNS → Edit**
- Optionally: a Discord webhook and/or an SMTP mailbox for notifications
- Any always-on Linux machine on your network for the real deployment (Raspberry Pi, Orange Pi, a spare mini-PC, a VM — it's lightweight enough for a Zero-class SBC)

## Quick start (local / development)

This just runs the service in your terminal for a quick look at the GUI — it's **not** the deployment method. If you're setting this up for real on a Pi or always-on server, skip straight to [SETUP.md](SETUP.md).

```bash
git clone https://github.com/eds35016/ddns-manager.git
cd ddns-manager
python3 -m venv venv
source venv/bin/activate   # venv\Scripts\activate on Windows
pip install -r requirements.txt
python ddns_service.py
```

On first run it generates an admin password and prints it once to the console — log in at `http://localhost:8080`, change the password immediately, then add your Cloudflare token/Zone ID in Settings.

**For a real always-on deployment** (systemd unit, dedicated user, firewall notes, Cloudflare/Discord/SMTP setup walkthrough, troubleshooting) see **[SETUP.md](SETUP.md)** — that's the full guide.

## Architecture

One Python process, two cooperating parts sharing a lock-guarded, atomically-persisted config:

- **Poller thread** — checks the public IP, reconciles DNS records with Cloudflare on every restart, updates anything that's tracked and changed, and fires notifications. Sleeps on an event so GUI changes (a new poll interval, a manual "Check now") wake it instantly instead of waiting for a restart.
- **Web GUI** (Flask, served by Waitress) — a login-gated dashboard, a full DNS record CRUD manager, and a settings page. Every route requires auth; every state-changing request is CSRF-protected.

See [SETUP.md](SETUP.md#how-it-works) for the file-by-file breakdown and the full configuration reference.

## Security

- Every page and API endpoint requires login; failed logins are rate-limited per IP.
- CSRF protection on all state-changing requests; session cookies are `HttpOnly`/`SameSite=Lax`; a strict CSP blocks inline scripts.
- The admin password is stored hashed, never in plaintext.
- Designed for **LAN-only use** — don't port-forward the GUI port to the internet. Full notes in [SETUP.md](SETUP.md#security-notes).

If you find a security issue, please open an issue or a private report rather than a public PR with exploit details.

## Contributing

Issues and pull requests are welcome — this is a small personal-utility-sized project, so please keep changes focused and consistent with the existing style (no external JS/CSS frameworks, no new dependencies without a good reason).

## License

[MIT](LICENSE) — do what you like with it.
