"""Autonomous VT hunter — discovers and scores kernel drivers from VirusTotal."""

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import scan_driver
from .framework_detect import FrameworkClassifier
from .scoring import AttackSurfaceScorer, AttackSurfaceScore

logger = logging.getLogger("driveratlas.hunter")

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRAMEWORKS_PATH = os.path.join(_PKG_ROOT, "signatures", "frameworks.yaml")
_CATEGORIES_PATH = os.path.join(_PKG_ROOT, "signatures", "api_categories.yaml")
_ATTACK_SURFACE_PATH = os.path.join(_PKG_ROOT, "signatures", "attack_surface.yaml")

DEFAULT_SEEN_PATH = os.path.expanduser("~/.driveratlas/seen.json")


@dataclass
class HuntResult:
    """A scored driver finding from hunting."""
    sha256: str
    name: str
    score: AttackSurfaceScore
    path: str = ""
    source: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "name": self.name,
            "score": self.score.to_dict(),
            "path": self.path,
            "source": self.source,
        }


class DriverHunter:
    """Discovers and scores kernel drivers from VT or local directories."""

    def __init__(self, seen_path: str | None = None):
        self.seen_path = seen_path or DEFAULT_SEEN_PATH
        self._seen = self._load_seen()
        self._classifier = None
        self._scorer = None

    @property
    def classifier(self):
        if self._classifier is None and os.path.exists(_FRAMEWORKS_PATH):
            self._classifier = FrameworkClassifier(_FRAMEWORKS_PATH)
        return self._classifier

    @property
    def scorer(self):
        if self._scorer is None:
            self._scorer = AttackSurfaceScorer(_ATTACK_SURFACE_PATH)
        return self._scorer

    def hunt_vt(
        self, queries: list[str] | None = None, limit: int = 50, min_score: float = 0.0,
    ) -> list[HuntResult]:
        """Search VT Intelligence for kernel drivers, scan, and score them."""
        try:
            import vt
        except ImportError:
            raise ImportError(
                "vt-py is required for VT hunting. "
                "Install with: pip install 'driveratlas[hunt]'"
            )

        vt_key = os.environ.get("VT_API_KEY")
        if not vt_key:
            raise ValueError("VT_API_KEY environment variable not set")

        if queries is None:
            queries = [
                'name:"*.sys" tag:signed size:5kb-500kb ls:7d+',
            ]

        results = []
        client = vt.Client(vt_key)
        try:
            for query in queries:
                logger.info(f"VT search: {query}")
                try:
                    search_iter = client.iterator(
                        "/intelligence/search",
                        params={"query": query, "descriptors_only": True},
                        limit=limit,
                    )
                    for file_obj in search_iter:
                        sha256 = file_obj.id.lower()
                        if sha256 in self._seen:
                            continue

                        name = getattr(file_obj, "meaningful_name", sha256[:12] + ".sys")

                        # Download to temp file
                        tmp = tempfile.NamedTemporaryFile(
                            delete=False, suffix=".sys", prefix="da_hunt_"
                        )
                        try:
                            client.download_file(sha256, tmp)
                            tmp.close()

                            result = self._scan_and_score(
                                tmp.name, name, sha256, "virustotal"
                            )
                            if result and result.score.total >= min_score:
                                results.append(result)

                            self._mark_seen(sha256)
                        finally:
                            try:
                                os.unlink(tmp.name)
                            except OSError:
                                pass
                except Exception as e:
                    logger.error(f"VT query failed: {e}")
        finally:
            client.close()

        results.sort(key=lambda r: r.score.total, reverse=True)
        return results

    def hunt_directory(
        self, path: str, recursive: bool = True, min_score: float = 0.0,
    ) -> list[HuntResult]:
        """Scan a local directory of drivers and return scored results."""
        targets = []
        if os.path.isfile(path):
            targets.append(path)
        elif os.path.isdir(path):
            if recursive:
                for root, _dirs, files in os.walk(path):
                    targets.extend(
                        os.path.join(root, f) for f in files if f.lower().endswith(".sys")
                    )
            else:
                targets.extend(
                    os.path.join(path, f)
                    for f in os.listdir(path) if f.lower().endswith(".sys")
                )

        results = []
        for t in sorted(targets):
            result = self._scan_and_score(t, os.path.basename(t), source="directory")
            if result and result.score.total >= min_score:
                results.append(result)

        results.sort(key=lambda r: r.score.total, reverse=True)
        return results

    def alert_telegram(
        self, findings: list[HuntResult], token: str, chat_id: str,
        min_score: float = 8.0,
    ) -> bool:
        """Send Telegram alert for high-scoring findings."""
        import requests

        alertable = [f for f in findings if f.score.total >= min_score]
        if not alertable:
            return False

        msg = f"*DriverAtlas Hunt Alert* — {len(alertable)} high-risk driver{'s' if len(alertable) > 1 else ''}\n\n"

        for i, finding in enumerate(alertable[:10], 1):
            risk = finding.score.risk_level.upper()
            msg += f"*{i}.* `{finding.name}` — *{finding.score.total:.1f}* [{risk}]\n"
            msg += f"   SHA256: `{finding.sha256[:16]}...`\n"
            top_flags = finding.score.flags[:2]
            if top_flags:
                msg += f"   {'; '.join(top_flags)}\n"
            msg += "\n"

        if len(alertable) > 10:
            msg += f"_...and {len(alertable) - 10} more_\n"

        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": msg,
                    "parse_mode": "Markdown",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                logger.info("Telegram alert sent successfully")
                return True
            logger.error(f"Telegram API error: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            logger.error(f"Telegram request failed: {e}")
            return False

    def _scan_and_score(
        self, path: str, name: str, sha256: str | None = None, source: str = "unknown",
    ) -> HuntResult | None:
        """Scan a single file and return a scored HuntResult."""
        cats_path = _CATEGORIES_PATH if os.path.exists(_CATEGORIES_PATH) else None
        try:
            profile = scan_driver(path, classifier=self.classifier, categories_path=cats_path)
            score = self.scorer.score(profile)
            return HuntResult(
                sha256=sha256 or profile.sha256,
                name=name,
                score=score,
                path=path,
                source=source,
            )
        except Exception as e:
            logger.warning(f"Failed to scan {name}: {e}")
            return None

    def _load_seen(self) -> set[str]:
        """Load seen SHA256 hashes from persistent JSON file."""
        if os.path.exists(self.seen_path):
            try:
                with open(self.seen_path) as f:
                    data = json.load(f)
                return set(data.get("seen", []))
            except (json.JSONDecodeError, KeyError):
                return set()
        return set()

    def _mark_seen(self, sha256: str):
        """Add SHA256 to seen set and persist."""
        self._seen.add(sha256)
        self._save_seen()

    def _save_seen(self):
        """Persist seen hashes to disk."""
        os.makedirs(os.path.dirname(self.seen_path), exist_ok=True)
        with open(self.seen_path, "w") as f:
            json.dump({"seen": sorted(self._seen)}, f, indent=2)
