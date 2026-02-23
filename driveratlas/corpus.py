"""YAML corpus management for DriverAtlas."""

import os
from datetime import datetime, timezone
from typing import Optional

import yaml


class Corpus:
    """Manages YAML corpus entries organized by category."""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = corpus_dir

    def list_categories(self) -> list[str]:
        """List all category directories in the corpus."""
        if not os.path.isdir(self.corpus_dir):
            return []
        return sorted(
            d for d in os.listdir(self.corpus_dir)
            if os.path.isdir(os.path.join(self.corpus_dir, d))
            and not d.startswith(".")
        )

    def list_entries(self, category: str) -> list[str]:
        """List all YAML entry names in a category (without .yaml extension)."""
        cat_dir = os.path.join(self.corpus_dir, category)
        if not os.path.isdir(cat_dir):
            return []
        return sorted(
            os.path.splitext(f)[0]
            for f in os.listdir(cat_dir)
            if f.endswith(".yaml") and not f.startswith(".")
        )

    def get_entry(self, category: str, name: str) -> Optional[dict]:
        """Load a corpus entry by category and name."""
        path = os.path.join(self.corpus_dir, category, f"{name}.yaml")
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def save_entry(self, category: str, name: str, data: dict) -> str:
        """Save a corpus entry. Returns the path written."""
        cat_dir = os.path.join(self.corpus_dir, category)
        os.makedirs(cat_dir, exist_ok=True)
        path = os.path.join(cat_dir, f"{name}.yaml")
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
        return path

    def import_from_profile(
        self,
        profile,
        category: str,
        vendor: str,
        display_name: Optional[str] = None,
        source: Optional[str] = None,
    ) -> str:
        """Convert a DriverProfile into a corpus entry and save it.

        Returns the path to the saved YAML file.
        """
        entry_name = display_name or os.path.splitext(profile.name)[0]
        slug = entry_name.lower().replace(" ", "_").replace("-", "_")

        data = {
            "name": entry_name,
            "filename": profile.name,
            "category": category,
            "vendor": vendor,
            "source": source or "local_scan",
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "sha256": profile.sha256,
            "size": profile.size,
            "machine": profile.machine,
            "subsystem": profile.subsystem,
            "linker_version": profile.linker_version,
            "signer": profile.signer,
            "product_name": profile.product_name,
            "file_description": profile.file_description,
            "company_name": profile.company_name,
            "file_version": profile.file_version,
            "framework": profile.framework,
            "framework_confidence": round(profile.framework_confidence, 3),
            "secondary_frameworks": profile.secondary_frameworks,
            "import_count": profile.import_count,
            "api_categories": profile.api_categories,
            "device_names": profile.device_names,
            "symbolic_links": profile.symbolic_links,
            "registry_paths": profile.registry_paths,
            "sections": profile.sections,
        }

        return self.save_entry(category, slug, data)
