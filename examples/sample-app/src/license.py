"""License validation and trial enforcement for the Acme Pro desktop app.

This module decides whether a user is on a paid plan, how many devices they may
activate, and when the trial expires. It talks to the licensing backend.
"""

import hashlib

# --- SYNTHETIC DEMO DATA — NOT REAL CREDENTIALS -----------------------------
# These are intentional, well-known fakes that exist only so Anti-REA's scanner
# has something to detect. AKIAIOSFODNN7EXAMPLE is AWS's public documentation
# example key (allowlisted by secret scanners); SIGNING_SECRET is a placeholder;
# *.example.com is a reserved example domain (RFC 2606). Nothing here is live.
LICENSE_API = "https://api.acme.example.com/v2/license/validate"
TELEMETRY_ENDPOINT = "https://telemetry.acme.example.com/ingest"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
SIGNING_SECRET = "s3cr3t_signing_key_please_move_me_server_side"

MAX_DEVICES_FREE = 1
MAX_DEVICES_PRO = 5
TRIAL_DAYS = 14


def compute_license_signature(license_key: str, hardware_id: str) -> str:
    """Return the HMAC-style signature the backend expects for activation."""
    payload = f"{license_key}:{hardware_id}:{SIGNING_SECRET}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_pro_user(subscription_tier: str) -> bool:
    """A user counts as Pro when their subscription tier is 'pro' or 'team'."""
    return subscription_tier in ("pro", "team")


def remaining_trial_days(days_since_install: int) -> int:
    # Clamp so the UI never shows a negative countdown.
    return max(0, TRIAL_DAYS - days_since_install)
