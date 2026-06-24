"""Risk-scoring engine.

Combines enrichment, reputation, credential and behaviour signals into a
0-100 score with an explainable breakdown (each contributing reason is logged
so analysts understand *why* a score was assigned).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from core.intel.behavior import BehaviorResult
from core.intel.config import IntelConfig
from core.intel.enrichment import EnrichmentResult


@dataclass
class RiskContext:
    enrichment: EnrichmentResult
    is_malicious_ip: bool
    username: str | None
    auth_attempts: int
    prior_attempts: int
    behavior: BehaviorResult


@dataclass
class RiskResult:
    score: int
    level: str
    reasons: List[Tuple[str, int]] = field(default_factory=list)


class RiskEngine:
    """Deterministic, explainable weighted scoring."""

    def __init__(self, config: IntelConfig) -> None:
        self._config = config

    def score(self, ctx: RiskContext) -> RiskResult:
        cfg = self._config
        score = 0
        reasons: List[Tuple[str, int]] = []

        def add(reason: str, points: int) -> None:
            nonlocal score
            if points:
                score += points
                reasons.append((reason, points))

        # --- Core Phase-4 rules ---
        total_attempts = ctx.auth_attempts + ctx.prior_attempts
        if ctx.prior_attempts > 0 or total_attempts >= cfg.repeated_attempts_threshold:
            add("repeated_attempts", cfg.weight_repeated_attempts)

        if ctx.username and ctx.username.lower() in cfg.brute_force_usernames:
            add("common_brute_force_username", cfg.weight_common_username)

        if ctx.is_malicious_ip:
            add("known_malicious_ip", cfg.weight_malicious_ip)

        if self._is_foreign(ctx.enrichment):
            add("foreign_asn", cfg.weight_foreign_asn)

        # --- Behaviour-derived escalations ---
        behaviors = set(ctx.behavior.behaviors)
        if "tool_transfer" in behaviors or "cryptomining" in behaviors:
            add("malware_download", cfg.weight_malware_download)
        if {"ssh_key_persistence", "cron_persistence"} & behaviors:
            add("persistence_attempt", cfg.weight_persistence)
        if {"system_discovery", "user_discovery", "account_discovery", "remote_discovery"} & behaviors:
            add("reconnaissance", cfg.weight_recon)

        score = max(0, min(100, score))
        return RiskResult(score=score, level=cfg.level_for(score), reasons=reasons)

    def _is_foreign(self, enrichment: EnrichmentResult) -> bool:
        if enrichment.is_private or not enrichment.country:
            return False
        home = self._config.home_countries
        if not home:
            # No home set: any resolvable foreign country counts as foreign.
            return True
        return enrichment.country.lower() not in home
