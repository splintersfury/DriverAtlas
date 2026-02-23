"""Attack surface scoring engine for DriverAtlas."""

import os
from dataclasses import dataclass, field

import yaml


@dataclass
class ScoreContribution:
    """A single rule evaluation result."""
    rule_id: str
    description: str
    weight: float
    matched: bool


@dataclass
class AttackSurfaceScore:
    """Final attack surface score with breakdown."""
    total: float
    risk_level: str
    contributions: list[ScoreContribution] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "risk_level": self.risk_level,
            "flags": self.flags,
            "contributions": [
                {"rule_id": c.rule_id, "description": c.description,
                 "weight": c.weight, "matched": c.matched}
                for c in self.contributions
            ],
        }


# Microsoft signer substrings (case-insensitive match)
_MICROSOFT_SIGNER_KEYWORDS = {"microsoft", "windows"}


class AttackSurfaceScorer:
    """Evaluates attack surface rules against a DriverProfile."""

    def __init__(self, rules_path: str | None = None):
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "signatures", "attack_surface.yaml",
            )
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        self.rules = data.get("rules", [])
        self.clamp_min = data.get("clamp", {}).get("min", 0.0)
        self.clamp_max = data.get("clamp", {}).get("max", 15.0)
        self.risk_levels = data.get("risk_levels", [])

        self._dispatch = {
            "has_device_names": self._check_has_device_names,
            "has_symbolic_links": self._check_has_symbolic_links,
            "has_ioctl_strings": self._check_has_ioctl_strings,
            "no_device_names": self._check_no_device_names,
            "has_import": self._check_has_import,
            "has_all_imports": self._check_has_all_imports,
            "missing_all_imports": self._check_missing_all_imports,
            "has_import_without": self._check_has_import_without,
            "size_below": self._check_size_below,
            "import_count_below": self._check_import_count_below,
            "import_count_above": self._check_import_count_above,
            "framework_equals": self._check_framework_equals,
            "signer_not_microsoft": self._check_signer_not_microsoft,
            "signer_is_microsoft": self._check_signer_is_microsoft,
        }

    def score(self, profile) -> AttackSurfaceScore:
        """Evaluate all rules against a DriverProfile and return the score."""
        flat_imports = self._all_imports_flat(profile)
        contributions = []
        raw_score = 0.0
        flags = []

        for rule in self.rules:
            check = rule["check"]
            params = rule.get("params")
            handler = self._dispatch.get(check)
            if handler is None:
                continue

            matched = handler(profile, flat_imports, params)
            weight = rule["weight"]
            contributions.append(ScoreContribution(
                rule_id=rule["id"],
                description=rule["description"],
                weight=weight,
                matched=matched,
            ))
            if matched:
                raw_score += weight
                flags.append(rule["description"])

        total = max(self.clamp_min, min(self.clamp_max, raw_score))
        risk_level = self._classify_risk(total)

        return AttackSurfaceScore(
            total=round(total, 1),
            risk_level=risk_level,
            contributions=contributions,
            flags=flags,
        )

    def _classify_risk(self, score: float) -> str:
        for level in self.risk_levels:
            if score >= level["min"]:
                return level["name"]
        return "minimal"

    @staticmethod
    def _all_imports_flat(profile) -> set[str]:
        """Flatten imports dict to a set of function names."""
        flat = set()
        imports = getattr(profile, "imports", {})
        for funcs in imports.values():
            flat.update(funcs)
        return flat

    # ── Check evaluators ──────────────────────────────────────────────

    @staticmethod
    def _check_has_device_names(profile, _flat, _params) -> bool:
        return bool(getattr(profile, "device_names", None))

    @staticmethod
    def _check_has_symbolic_links(profile, _flat, _params) -> bool:
        return bool(getattr(profile, "symbolic_links", None))

    @staticmethod
    def _check_has_ioctl_strings(profile, _flat, _params) -> bool:
        notables = getattr(profile, "notable_strings", [])
        return any(s.startswith("IOCTL_") for s in notables)

    @staticmethod
    def _check_no_device_names(profile, _flat, _params) -> bool:
        return not getattr(profile, "device_names", None)

    @staticmethod
    def _check_has_import(_profile, flat, params) -> bool:
        if not isinstance(params, list):
            params = [params]
        return any(p in flat for p in params)

    @staticmethod
    def _check_has_all_imports(_profile, flat, params) -> bool:
        if not isinstance(params, list):
            params = [params]
        return all(p in flat for p in params)

    @staticmethod
    def _check_missing_all_imports(_profile, flat, params) -> bool:
        if not isinstance(params, list):
            params = [params]
        return not any(p in flat for p in params)

    @staticmethod
    def _check_has_import_without(_profile, flat, params) -> bool:
        required = params.get("required") if isinstance(params, dict) else None
        excluded = params.get("excluded") if isinstance(params, dict) else None
        if not required or not excluded:
            return False
        return required in flat and excluded not in flat

    @staticmethod
    def _check_size_below(profile, _flat, params) -> bool:
        return getattr(profile, "size", 0) < int(params)

    @staticmethod
    def _check_import_count_below(profile, _flat, params) -> bool:
        return getattr(profile, "import_count", 0) < int(params)

    @staticmethod
    def _check_import_count_above(profile, _flat, params) -> bool:
        return getattr(profile, "import_count", 0) > int(params)

    @staticmethod
    def _check_framework_equals(profile, _flat, params) -> bool:
        return getattr(profile, "framework", "") == str(params)

    @staticmethod
    def _check_signer_not_microsoft(profile, _flat, _params) -> bool:
        signer = getattr(profile, "signer", None)
        if not signer:
            return False
        lower = signer.lower()
        return not any(kw in lower for kw in _MICROSOFT_SIGNER_KEYWORDS)

    @staticmethod
    def _check_signer_is_microsoft(profile, _flat, _params) -> bool:
        signer = getattr(profile, "signer", None)
        if not signer:
            return False
        lower = signer.lower()
        return any(kw in lower for kw in _MICROSOFT_SIGNER_KEYWORDS)
