"""Thin wrapper around the Cloudflare DNS records API.

Every function raises CloudflareError with Cloudflare's own error code and
message on failure so the GUI can show the real reason (bad token scope,
record already exists, etc.) instead of a generic failure.
"""

import logging

import requests

log = logging.getLogger(__name__)

API_BASE = "https://api.cloudflare.com/client/v4"
TIMEOUT = (5, 15)  # (connect, read) seconds

# Cloudflare error codes that mean the API token is bad/expired/mis-scoped.
AUTH_ERROR_CODES = {6003, 9109, 10000, 9106}

# Record types that support Cloudflare proxying.
PROXYABLE_TYPES = {"A", "AAAA", "CNAME"}


class CloudflareError(Exception):
    def __init__(self, message, code=None, http_status=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_status = http_status

    @property
    def is_auth_error(self):
        return self.code in AUTH_ERROR_CODES or self.http_status in (401, 403)


def _headers(api_token):
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }


def _request(method, path, api_token, **kwargs):
    try:
        resp = requests.request(
            method, f"{API_BASE}{path}", headers=_headers(api_token),
            timeout=TIMEOUT, **kwargs,
        )
    except requests.RequestException as exc:
        raise CloudflareError(f"Could not reach the Cloudflare API: {exc}") from exc

    try:
        body = resp.json()
    except ValueError:
        raise CloudflareError(
            f"Cloudflare returned a non-JSON response (HTTP {resp.status_code})",
            http_status=resp.status_code,
        )

    if not body.get("success"):
        errors = body.get("errors") or []
        if errors:
            first = errors[0]
            raise CloudflareError(
                first.get("message", "Unknown Cloudflare error"),
                code=first.get("code"),
                http_status=resp.status_code,
            )
        raise CloudflareError(
            f"Cloudflare request failed (HTTP {resp.status_code})",
            http_status=resp.status_code,
        )
    return body


def verify_token(api_token):
    """Check the token is valid and active. Returns the token status string."""
    body = _request("GET", "/user/tokens/verify", api_token)
    return body["result"].get("status", "unknown")


def list_dns_records(api_token, zone_id):
    """Return every DNS record in the zone, following pagination."""
    records = []
    page = 1
    while True:
        body = _request(
            "GET", f"/zones/{zone_id}/dns_records", api_token,
            params={"per_page": 100, "page": page},
        )
        records.extend(body["result"])
        info = body.get("result_info", {})
        if page >= info.get("total_pages", 1):
            break
        page += 1
    return records


def get_dns_record(api_token, zone_id, record_id):
    body = _request("GET", f"/zones/{zone_id}/dns_records/{record_id}", api_token)
    return body["result"]


def create_dns_record(api_token, zone_id, payload):
    body = _request("POST", f"/zones/{zone_id}/dns_records", api_token, json=payload)
    return body["result"]


def update_dns_record_full(api_token, zone_id, record_id, payload):
    """PUT — full overwrite, used by GUI edits where the form owns all fields."""
    body = _request(
        "PUT", f"/zones/{zone_id}/dns_records/{record_id}", api_token, json=payload,
    )
    return body["result"]


def patch_dns_record_content(api_token, zone_id, record_id, new_ip):
    """PATCH only the content — used by DDNS updates.

    A partial update inherently preserves name/ttl/proxied/comment, so a
    record edited in the GUI or Cloudflare dashboard between polls is never
    clobbered by a read-modify-write race.
    """
    body = _request(
        "PATCH", f"/zones/{zone_id}/dns_records/{record_id}", api_token,
        json={"content": new_ip},
    )
    return body["result"]


def delete_dns_record(api_token, zone_id, record_id):
    _request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", api_token)
