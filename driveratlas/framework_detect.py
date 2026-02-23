"""Import-based framework classification for Windows kernel drivers."""

import logging
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger("driveratlas.framework_detect")


@dataclass
class FrameworkMatch:
    """A detected framework with confidence score."""
    name: str
    score: float
    confidence: float
    matched_symbols: list = field(default_factory=list)


class FrameworkClassifier:
    """Classifies driver framework from import table using weighted rules."""

    CONFIDENCE_THRESHOLD = 0.3

    def __init__(self, rules_path: str):
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
        self.frameworks = data.get("frameworks", {})

    def classify(self, imports: dict) -> tuple[Optional[FrameworkMatch], list[FrameworkMatch]]:
        """Classify driver framework from imports.

        Returns (primary_match, secondary_matches).
        primary is the highest-scoring framework, secondary are any others
        with confidence >= 0.2.
        """
        # Build flat set of (dll, symbol) for fast lookup
        import_set = set()
        for dll, funcs in imports.items():
            dll_lower = dll.lower()
            for func in funcs:
                import_set.add((dll_lower, func))

        candidates = []
        anchor_hits = {}  # fw_name → anchor confidence (0-1)

        for fw_name, fw_def in self.frameworks.items():
            score, total_weight, matched, anchor_conf = self._score_framework(fw_def, import_set)

            if total_weight == 0:
                continue

            confidence = score / total_weight
            anchor_hits[fw_name] = anchor_conf
            candidates.append(FrameworkMatch(
                name=fw_name,
                score=score,
                confidence=confidence,
                matched_symbols=matched,
            ))

        if not candidates:
            return None, []

        # Separate fallback from normal
        normal = [c for c in candidates if not self.frameworks.get(c.name, {}).get("is_fallback")]
        fallback = [c for c in candidates if self.frameworks.get(c.name, {}).get("is_fallback")]

        # Primary: highest score among non-fallback.
        # Qualifies if overall confidence >= threshold OR anchor confidence >= 0.5
        # (anchors matching strongly is sufficient even without supporting imports).
        normal.sort(key=lambda x: x.score, reverse=True)
        fallback.sort(key=lambda x: x.score, reverse=True)

        primary = None
        for c in normal:
            if c.confidence >= self.CONFIDENCE_THRESHOLD or anchor_hits.get(c.name, 0) >= 0.5:
                primary = c
                break

        if primary is None and fallback and fallback[0].matched_symbols:
            # wdm_raw fallback: only if IoCreateDevice present and no normal framework qualified
            primary = fallback[0]

        if primary is None:
            return None, []

        # Secondary: any framework (excluding primary) with confidence >= 0.2
        secondary = []
        for c in candidates:
            if c.name == primary.name:
                continue
            if c.confidence >= 0.2:
                secondary.append(c)
        secondary.sort(key=lambda x: x.score, reverse=True)

        return primary, secondary

    def _score_framework(self, fw_def: dict, import_set: set) -> tuple[float, float, list, float]:
        """Score a framework definition against imports.

        Returns (score, total_possible_weight, matched_symbols, anchor_confidence).
        """
        score = 0.0
        total_weight = 0.0
        matched = []

        # Score anchors
        anchors = fw_def.get("anchors", {})
        anchor_dll = anchors.get("dll", "").lower()
        anchor_syms = anchors.get("symbols", [])
        anchor_weight = anchors.get("weight", 5.0)

        anchor_matched = 0
        if anchor_syms:
            total_weight += anchor_weight
            for sym in anchor_syms:
                if (anchor_dll, sym) in import_set:
                    score += anchor_weight / len(anchor_syms)
                    matched.append(sym)
                    anchor_matched += 1

        anchor_conf = anchor_matched / len(anchor_syms) if anchor_syms else 0.0

        # Score supporting imports
        for sup in fw_def.get("supporting", []):
            sup_dll = sup.get("dll", "").lower()
            sup_sym = sup.get("symbol", "")
            sup_weight = sup.get("weight", 1.0)
            total_weight += sup_weight
            if (sup_dll, sup_sym) in import_set:
                score += sup_weight
                matched.append(sup_sym)

        return score, total_weight, matched, anchor_conf
