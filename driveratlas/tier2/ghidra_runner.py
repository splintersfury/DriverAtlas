"""Ghidra headless analysis runner — orchestrates analyzeHeadless for driver binaries."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("driveratlas.tier2.ghidra_runner")

# Default Ghidra install locations
_GHIDRA_SEARCH_PATHS = [
    os.environ.get("GHIDRA_HOME", ""),
    "/opt/ghidra",
    os.path.expanduser("~/ghidra"),
    "/usr/local/ghidra",
]

SCRIPT_DIR = Path(__file__).parent.parent.parent / "ghidra_scripts"


def find_ghidra_home() -> Optional[str]:
    """Locate Ghidra installation directory."""
    for path in _GHIDRA_SEARCH_PATHS:
        if not path:
            continue
        analyze = os.path.join(path, "support", "analyzeHeadless")
        if os.path.isfile(analyze):
            return path
    return None


def find_analyze_headless(ghidra_home: Optional[str] = None) -> Optional[str]:
    """Locate the analyzeHeadless script."""
    home = ghidra_home or find_ghidra_home()
    if not home:
        return None
    path = os.path.join(home, "support", "analyzeHeadless")
    return path if os.path.isfile(path) else None


class GhidraRunner:
    """Runs Ghidra headless analysis on a driver binary and collects results."""

    def __init__(
        self,
        ghidra_home: Optional[str] = None,
        timeout: int = 600,
        jvm_max_mem: str = "4G",
    ):
        self.ghidra_home = ghidra_home or find_ghidra_home()
        if not self.ghidra_home:
            raise FileNotFoundError(
                "Ghidra not found. Set GHIDRA_HOME or install to /opt/ghidra"
            )

        self.analyze_headless = find_analyze_headless(self.ghidra_home)
        if not self.analyze_headless:
            raise FileNotFoundError(
                f"analyzeHeadless not found in {self.ghidra_home}/support/"
            )

        self.timeout = timeout
        self.jvm_max_mem = jvm_max_mem
        self.script_dir = str(SCRIPT_DIR)

    def analyze(
        self,
        driver_path: str,
        output_dir: Optional[str] = None,
        pdb_path: Optional[str] = None,
        scripts: Optional[list] = None,
    ) -> dict:
        """Run Ghidra headless analysis on a driver binary.

        Args:
            driver_path: Path to the .sys file
            output_dir: Where to write results (default: temp dir)
            pdb_path: Optional PDB symbol file path
            scripts: List of post-scripts to run (default: ExportDriverDispatch.py)

        Returns:
            dict with dispatch_table.json contents, or {"error": "..."} on failure
        """
        driver_path = os.path.abspath(driver_path)
        if not os.path.isfile(driver_path):
            return {"error": f"Driver not found: {driver_path}"}

        # Create temp project directory (cleaned up after)
        project_dir = tempfile.mkdtemp(prefix="ghidra_atlas_")
        project_name = "DriverAtlasAnalysis"

        # Output directory for script results
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        else:
            output_dir = tempfile.mkdtemp(prefix="ghidra_out_")

        if scripts is None:
            scripts = ["ExportDriverDispatch.py"]

        try:
            result = self._run_headless(
                driver_path, project_dir, project_name,
                output_dir, pdb_path, scripts,
            )
            return result
        finally:
            # Clean up temp project (but keep output_dir if user-specified)
            shutil.rmtree(project_dir, ignore_errors=True)

    def _run_headless(
        self,
        driver_path: str,
        project_dir: str,
        project_name: str,
        output_dir: str,
        pdb_path: Optional[str],
        scripts: list,
    ) -> dict:
        """Execute analyzeHeadless and parse results."""
        cmd = [
            self.analyze_headless,
            project_dir,
            project_name,
            "-import", driver_path,
            "-overwrite",
            "-scriptPath", self.script_dir,
        ]

        # Add pre-script for PDB loading if provided
        if pdb_path and os.path.isfile(pdb_path):
            cmd.extend(["-preScript", "LoadPDB.py", pdb_path])

        # Add post-scripts
        for script in scripts:
            cmd.extend(["-postScript", script, output_dir])

        # JVM memory
        env = os.environ.copy()
        env["JAVA_TOOL_OPTIONS"] = f"-Xmx{self.jvm_max_mem}"

        logger.info(f"Running Ghidra headless on {os.path.basename(driver_path)}...")
        start = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            logger.error(f"Ghidra timed out after {elapsed:.0f}s")
            return {"error": f"Ghidra timed out after {self.timeout}s"}
        except FileNotFoundError as e:
            return {"error": f"analyzeHeadless not executable: {e}"}

        elapsed = time.time() - start
        logger.info(f"Ghidra finished in {elapsed:.1f}s (exit code {proc.returncode})")

        if proc.returncode != 0:
            # Log stderr but don't fail — Ghidra sometimes returns non-zero even on success
            logger.warning(f"Ghidra stderr:\n{proc.stderr[-2000:]}")

        # Parse dispatch_table.json
        dispatch_path = os.path.join(output_dir, "dispatch_table.json")
        if os.path.isfile(dispatch_path):
            try:
                with open(dispatch_path) as f:
                    result = json.load(f)
                result["_analysis_seconds"] = round(elapsed, 1)
                result["_ghidra_home"] = self.ghidra_home
                return result
            except json.JSONDecodeError as e:
                return {"error": f"Failed to parse dispatch_table.json: {e}"}
        else:
            # Check if Ghidra produced any output
            logger.error(f"dispatch_table.json not found in {output_dir}")
            return {
                "error": "dispatch_table.json not produced",
                "_stderr_tail": proc.stderr[-1000:] if proc.stderr else "",
                "_stdout_tail": proc.stdout[-1000:] if proc.stdout else "",
            }

    def version(self) -> str:
        """Get Ghidra version string."""
        app_props = os.path.join(self.ghidra_home, "Ghidra", "application.properties")
        if os.path.isfile(app_props):
            with open(app_props) as f:
                for line in f:
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
        return "unknown"
