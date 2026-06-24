"""GeoIP + ASN enrichment service.

Uses MaxMind GeoLite2 databases when available and degrades gracefully when
they are missing (e.g. dev environments without the .mmdb files). Private and
reserved addresses are resolved locally without any lookup.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

from core.intel.config import IntelConfig

logger = logging.getLogger("sentinelssh.intel.enrichment")

try:  # geoip2 is optional; absence simply disables MaxMind lookups.
    import geoip2.database  # type: ignore
    import geoip2.errors  # type: ignore

    _GEOIP_AVAILABLE = True
except Exception:  # noqa: BLE001
    _GEOIP_AVAILABLE = False


@dataclass
class EnrichmentResult:
    country: Optional[str] = None          # ISO alpha-2, e.g. "RU"
    country_name: Optional[str] = None     # Human readable, e.g. "Russia"
    asn: Optional[str] = None              # e.g. "AS14061"
    isp: Optional[str] = None              # Organisation / ISP name
    is_private: bool = False

    @property
    def is_foreign(self) -> bool:
        return bool(self.country) and not self.is_private


class EnrichmentService:
    """Resolves geolocation and network ownership for an IP address."""

    def __init__(self, config: IntelConfig) -> None:
        self._config = config
        self._city_reader = self._open_reader(config.geoip_city_db, "city")
        self._asn_reader = self._open_reader(config.geoip_asn_db, "asn")

    def _open_reader(self, path: str, kind: str):
        if not _GEOIP_AVAILABLE:
            return None
        try:
            from pathlib import Path

            if not Path(path).exists():
                logger.info("GeoIP %s DB not found at %s; enrichment will degrade", kind, path)
                return None
            return geoip2.database.Reader(path)
        except Exception:  # noqa: BLE001
            logger.exception("failed opening GeoIP %s DB at %s", kind, path)
            return None

    def enrich(self, ip: str) -> EnrichmentResult:
        result = EnrichmentResult()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return result

        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            result.is_private = True
            result.country = "LO"
            result.country_name = "Local/Private"
            result.isp = "Private Network"
            return result

        self._fill_geo(ip, result)
        self._fill_asn(ip, result)
        return result

    def _fill_geo(self, ip: str, result: EnrichmentResult) -> None:
        if self._city_reader is None:
            return
        try:
            resp = self._city_reader.city(ip)
            result.country = resp.country.iso_code
            result.country_name = resp.country.name
        except Exception:  # noqa: BLE001 - unknown IP / lookup miss
            logger.debug("geo lookup miss for %s", ip)

    def _fill_asn(self, ip: str, result: EnrichmentResult) -> None:
        if self._asn_reader is None:
            return
        try:
            resp = self._asn_reader.asn(ip)
            if resp.autonomous_system_number:
                result.asn = f"AS{resp.autonomous_system_number}"
            result.isp = resp.autonomous_system_organization
        except Exception:  # noqa: BLE001
            logger.debug("asn lookup miss for %s", ip)

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            try:
                if reader is not None:
                    reader.close()
            except Exception:  # noqa: BLE001
                pass
