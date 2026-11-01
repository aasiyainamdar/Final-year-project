
# ============================================================
# NFA - SIMULATED THREAT BLOCKING MODULE
# ============================================================

from collections import deque
from threading import Lock
from datetime import datetime

import ipaddress
import time

# Simulation settings
BLOCK_DURATION = 300          # 5 minutes
PORT_SCAN_THRESHOLD = 5       # Unique destination ports
PORT_SCAN_WINDOW = 10         # Seconds

blocked_ips = {}
block_logs = deque(maxlen=200)
block_lock = Lock()


def block_ip(ip, reason, severity="High"):
    """Add an IP to the simulated blocklist."""

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "success": False,
            "message": "Invalid IP address"
        }

    # Only high-severity events trigger automatic blocking.
    if severity != "High":
        return {
            "success": False,
            "message": "Severity is below the automatic block threshold"
        }

    now = time.time()

    with block_lock:
        existing = blocked_ips.get(ip)

        if existing and existing["expires_at"] > now:
            return {
                "success": True,
                "already_blocked": True,
                "message": "IP is already blocked in simulation"
            }

        blocked_ips[ip] = {
            "reason": reason,
            "severity": severity,
            "blocked_at": now,
            "expires_at": now + BLOCK_DURATION
        }

        block_logs.appendleft({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "action": "SIMULATED BLOCK",
            "duration_seconds": BLOCK_DURATION
        })

    print(f"[SIMULATED BLOCK] {ip} | {reason}")

    return {
        "success": True,
        "already_blocked": False,
        "message": "IP added to simulated blocklist"
    }


def is_blocked(ip):
    """Check whether an IP is currently blocked in simulation."""

    now = time.time()

    with block_lock:
        entry = blocked_ips.get(ip)

        if not entry:
            return False

        if entry["expires_at"] <= now:
            del blocked_ips[ip]
            return False

        return True


def get_blocked_ips():
    """Return active simulated blocks."""

    now = time.time()
    active = []

    with block_lock:
        expired = [
            ip for ip, entry in blocked_ips.items()
            if entry["expires_at"] <= now
        ]

        for ip in expired:
            del blocked_ips[ip]

        for ip, entry in blocked_ips.items():
            active.append({
                "ip": ip,
                "reason": entry["reason"],
                "severity": entry["severity"],
                "blocked_at": datetime.fromtimestamp(
                    entry["blocked_at"]
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "expires_in_seconds": max(
                    0, int(entry["expires_at"] - now)
                )
            })

    return active


def get_block_logs():
    """Return simulated block history."""

    with block_lock:
        return list(block_logs)


def unblock_ip(ip):
    """Remove an IP from the simulated blocklist."""

    with block_lock:
        if ip not in blocked_ips:
            return False

        del blocked_ips[ip]

        block_logs.appendleft({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "reason": "Manually removed from simulated blocklist",
            "severity": "Info",
            "action": "SIMULATED UNBLOCK",
            "duration_seconds": 0
        })

    return True
