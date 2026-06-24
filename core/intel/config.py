"""Configuration for the threat-intelligence layer (env-driven, with defaults).

Every weight and threshold is tunable without code changes so analysts can
calibrate scoring to their environment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Set


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_set(name: str, default: Set[str]) -> Set[str]:
    raw = os.getenv(name)
    if not raw:
        return default
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


# Usernames commonly hammered by SSH brute-force botnets.
DEFAULT_BRUTE_FORCE_USERNAMES: Set[str] = {
    "root", "admin", "administrator", "user", "test", "guest", "oracle",
    "postgres", "ubuntu", "pi", "ftpuser", "git", "deploy", "mysql",
    "support", "manager", "tomcat", "nagios", "www-data", "service",
}


@dataclass
class IntelConfig:
    """Risk weights, thresholds and reference data for the intel layer."""

    # --- Risk weights (Phase 4 spec) ---
    weight_repeated_attempts: int = field(default_factory=lambda: _env_int("RISK_W_REPEATED", 20))
    weight_common_username: int = field(default_factory=lambda: _env_int("RISK_W_USERNAME", 15))
    weight_malicious_ip: int = field(default_factory=lambda: _env_int("RISK_W_MALICIOUS", 40))
    weight_foreign_asn: int = field(default_factory=lambda: _env_int("RISK_W_FOREIGN", 10))

    # --- Behaviour-derived weights ---
    weight_malware_download: int = field(default_factory=lambda: _env_int("RISK_W_MALWARE", 20))
    weight_persistence: int = field(default_factory=lambda: _env_int("RISK_W_PERSISTENCE", 15))
    weight_recon: int = field(default_factory=lambda: _env_int("RISK_W_RECON", 5))

    # --- Thresholds ---
    repeated_attempts_threshold: int = field(
        default_factory=lambda: _env_int("RISK_REPEATED_THRESHOLD", 3)
    )
    history_window_hours: int = field(default_factory=lambda: _env_int("RISK_HISTORY_HOURS", 24))

    # Risk band boundaries (inclusive upper bounds).
    low_max: int = field(default_factory=lambda: _env_int("RISK_LOW_MAX", 30))
    medium_max: int = field(default_factory=lambda: _env_int("RISK_MEDIUM_MAX", 70))

    # ISO-3166 alpha-2 codes considered "home"; anything else counts as foreign.
    home_countries: Set[str] = field(
        default_factory=lambda: _env_set("RISK_HOME_COUNTRIES", set())
    )

    brute_force_usernames: Set[str] = field(
        default_factory=lambda: _env_set("RISK_BRUTE_USERNAMES", DEFAULT_BRUTE_FORCE_USERNAMES)
    )

    # --- Data sources ---
    geoip_city_db: str = field(default_factory=lambda: os.getenv("GEOIP_CITY_DB", "data/GeoLite2-City.mmdb"))
    geoip_asn_db: str = field(default_factory=lambda: os.getenv("GEOIP_ASN_DB", "data/GeoLite2-ASN.mmdb"))
    threat_feed_path: str = field(default_factory=lambda: os.getenv("THREAT_FEED_PATH", "data/threat_feed.txt"))

    def level_for(self, score: int) -> str:
        if score <= self.low_max:
            return "low"
        if score <= self.medium_max:
            return "medium"
        return "high"
