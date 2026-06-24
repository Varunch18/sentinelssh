"""IP reputation service backed by a local threat-feed file.

The feed is a newline-delimited list of IPs and/or CIDR ranges (comments with
'#' allowed). Kept local so the honeypot has no runtime network dependency; in
production this file can be refreshed from external feeds (e.g. AbuseIPDB,
FireHOL) via a cron job without touching code.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("sentinelssh.intel.reputation")


@dataclass
class ReputationResult:
    is_malicious: bool = False
    reputation: int = 0  # 0 (clean) .. 100 (known bad)
    source: Optional[str] = None


class ReputationService:
    """Matches IPs against a cached set of malicious networks."""

    def __init__(self, feed_path: str) -> None:
        self._feed_path = Path(feed_path)
        self._networks: List[ipaddress._BaseNetwork] = []
        self._load()

    def _load(self) -> None:
        if not self._feed_path.exists():
            logger.info("threat feed not found at %s; reputation checks disabled", self._feed_path)
            return
        count = 0
        for line in self._feed_path.read_text(encoding="utf-8").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
                count += 1
            except ValueError:
                logger.warning("invalid threat-feed entry skipped: %r", entry)
        logger.info("loaded %d malicious networks from threat feed", count)

    def check(self, ip: str) -> ReputationResult:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ReputationResult()
        for net in self._networks:
            if addr in net:
                return ReputationResult(is_malicious=True, reputation=100, source="local_feed")
        return ReputationResult()
