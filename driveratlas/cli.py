"""DriverAtlas CLI — scan, import, and manage driver corpus."""

import json
import logging
import os
import sys
import time

import click
import yaml
from rich.console import Console
from rich.table import Table

from .scanner import scan_driver, DriverProfile
from .framework_detect import FrameworkClassifier
from .scoring import AttackSurfaceScorer
from .corpus import Corpus

console = Console()

# Resolve paths relative to package root
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRAMEWORKS_PATH = os.path.join(_PKG_ROOT, "signatures", "frameworks.yaml")
_CATEGORIES_PATH = os.path.join(_PKG_ROOT, "signatures", "api_categories.yaml")
_CORPUS_DIR = os.path.join(_PKG_ROOT, "corpus")
_ATTACK_SURFACE_PATH = os.path.join(_PKG_ROOT, "signatures", "attack_surface.yaml")


def _get_classifier():
    if os.path.exists(_FRAMEWORKS_PATH):
        return FrameworkClassifier(_FRAMEWORKS_PATH)
    console.print("[yellow]Warning: frameworks.yaml not found, framework detection disabled[/]")
    return None


@click.group()
def main():
    """DriverAtlas — Windows kernel driver structural analysis toolkit."""
    pass


@main.command()
@click.argument("path")
@click.option("-r", "--recursive", is_flag=True, help="Scan directory recursively for .sys files")
@click.option("-f", "--format", "fmt", type=click.Choice(["table", "yaml", "json"]), default="table")
@click.option("-o", "--output", type=click.Path(), help="Write output to file")
def scan(path, recursive, fmt, output):
    """Scan a driver (.sys) or directory of drivers."""
    classifier = _get_classifier()
    cats_path = _CATEGORIES_PATH if os.path.exists(_CATEGORIES_PATH) else None

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
                os.path.join(path, f) for f in os.listdir(path) if f.lower().endswith(".sys")
            )
    else:
        console.print(f"[red]Path not found:[/] {path}")
        sys.exit(1)

    if not targets:
        console.print("[yellow]No .sys files found.[/]")
        return

    profiles = []
    for t in sorted(targets):
        try:
            p = scan_driver(t, classifier=classifier, categories_path=cats_path)
            profiles.append(p)
        except Exception as e:
            console.print(f"[red]Error scanning {t}:[/] {e}")

    if not profiles:
        return

    if fmt == "table":
        _print_table(profiles)
    elif fmt == "yaml":
        text = yaml.dump([p.to_dict() for p in profiles], default_flow_style=False, sort_keys=False)
        if output:
            _write_output(output, text)
        else:
            console.print(text)
    elif fmt == "json":
        text = json.dumps([p.to_dict() for p in profiles], indent=2, default=str)
        if output:
            _write_output(output, text)
        else:
            console.print(text)


def _profile_from_yaml(path: str) -> DriverProfile:
    """Reconstruct a DriverProfile from a corpus YAML entry."""
    with open(path) as f:
        d = yaml.safe_load(f)
    # Corpus entries don't store the raw imports dict — rebuild from api_categories
    # which stores {category: [func_names]}. Put all funcs under a synthetic DLL key
    # so the scorer's flat import lookup works.
    imports = d.get("imports", {})
    if not imports:
        all_funcs = []
        for funcs in d.get("api_categories", {}).values():
            all_funcs.extend(funcs)
        if all_funcs:
            imports = {"ntoskrnl.exe": all_funcs}
    return DriverProfile(
        name=d.get("filename", d.get("name", os.path.basename(path))),
        sha256=d.get("sha256", ""),
        size=d.get("size", 0),
        signer=d.get("signer"),
        framework=d.get("framework", "unknown"),
        framework_confidence=d.get("framework_confidence", 0.0),
        import_count=d.get("import_count", 0),
        imports=imports,
        device_names=d.get("device_names", []),
        symbolic_links=d.get("symbolic_links", []),
        notable_strings=d.get("notable_strings", []),
        company_name=d.get("company_name"),
        product_name=d.get("product_name"),
        file_description=d.get("file_description"),
    )


@main.command()
@click.argument("path")
@click.option("-r", "--recursive", is_flag=True, help="Scan directory recursively for .sys/.yaml files")
@click.option("-f", "--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--min-score", type=float, default=0.0, help="Only show drivers with score >= this value")
@click.option("-o", "--output", type=click.Path(), help="Write output to file")
def rank(path, recursive, fmt, min_score, output):
    """Rank drivers by attack surface score.

    Accepts .sys binaries (scanned live) or .yaml corpus entries.
    """
    classifier = _get_classifier()
    cats_path = _CATEGORIES_PATH if os.path.exists(_CATEGORIES_PATH) else None
    scorer = AttackSurfaceScorer(_ATTACK_SURFACE_PATH)

    _RANKABLE = (".sys", ".yaml", ".yml")
    targets = []
    if os.path.isfile(path):
        targets.append(path)
    elif os.path.isdir(path):
        if recursive:
            for root, _dirs, files in os.walk(path):
                targets.extend(
                    os.path.join(root, f) for f in files if f.lower().endswith(_RANKABLE)
                )
        else:
            targets.extend(
                os.path.join(path, f) for f in os.listdir(path) if f.lower().endswith(_RANKABLE)
            )
    else:
        console.print(f"[red]Path not found:[/] {path}")
        sys.exit(1)

    if not targets:
        console.print("[yellow]No .sys or .yaml files found.[/]")
        return

    results = []
    for t in sorted(targets):
        try:
            if t.lower().endswith((".yaml", ".yml")):
                profile = _profile_from_yaml(t)
            else:
                profile = scan_driver(t, classifier=classifier, categories_path=cats_path)
            score = scorer.score(profile)
            if score.total >= min_score:
                results.append((profile, score))
        except Exception as e:
            console.print(f"[red]Error scanning {t}:[/] {e}")

    # Sort by score descending
    results.sort(key=lambda x: x[1].total, reverse=True)

    if not results:
        console.print("[yellow]No drivers matched the criteria.[/]")
        return

    if fmt == "json":
        data = []
        for profile, score in results:
            entry = profile.to_dict()
            entry["attack_surface"] = score.to_dict()
            data.append(entry)
        text = json.dumps(data, indent=2, default=str)
        if output:
            _write_output(output, text)
        else:
            console.print(text)
    else:
        _print_rank_table(results)


def _print_rank_table(results):
    """Print a color-coded ranking table."""
    table = Table(title="DriverAtlas Attack Surface Ranking", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Driver", style="cyan", no_wrap=True)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Risk", width=10)
    table.add_column("Framework", style="green")
    table.add_column("Size")
    table.add_column("Imports", justify="right")
    table.add_column("Signer")
    table.add_column("Key Flags")

    for i, (profile, score) in enumerate(results, 1):
        # Color-code score
        if score.total >= 8.0:
            score_str = f"[bold red]{score.total:.1f}[/]"
            risk_str = f"[bold red]{score.risk_level}[/]"
        elif score.total >= 5.0:
            score_str = f"[yellow]{score.total:.1f}[/]"
            risk_str = f"[yellow]{score.risk_level}[/]"
        else:
            score_str = f"[green]{score.total:.1f}[/]"
            risk_str = f"[green]{score.risk_level}[/]"

        signer = profile.signer or "-"
        if len(signer) > 25:
            signer = signer[:22] + "..."

        # Show top 3 flags
        top_flags = score.flags[:3]
        flags_str = "; ".join(f[:40] for f in top_flags)
        if len(score.flags) > 3:
            flags_str += f" (+{len(score.flags) - 3})"

        table.add_row(
            str(i),
            profile.name,
            score_str,
            risk_str,
            profile.framework,
            f"{profile.size:,}",
            str(profile.import_count),
            signer,
            flags_str,
        )

    console.print(table)


def _print_table(profiles):
    """Print a Rich table summary of scanned profiles."""
    if len(profiles) == 1:
        _print_detail(profiles[0])
        return

    table = Table(title="DriverAtlas Scan Results", show_lines=True)
    table.add_column("Driver", style="cyan", no_wrap=True)
    table.add_column("Machine")
    table.add_column("Framework", style="green")
    table.add_column("Confidence")
    table.add_column("Imports")
    table.add_column("Signer")
    table.add_column("Size")

    for p in profiles:
        conf = f"{p.framework_confidence:.0%}" if p.framework_confidence else "-"
        signer = (p.signer[:30] + "...") if p.signer and len(p.signer) > 30 else (p.signer or "-")
        table.add_row(
            p.name,
            p.machine,
            p.framework,
            conf,
            str(p.import_count),
            signer,
            f"{p.size:,}",
        )

    console.print(table)


def _print_detail(p):
    """Print detailed Rich output for a single profile."""
    console.print(f"\n[bold cyan]{p.name}[/]")
    console.print(f"  SHA256:     {p.sha256}")
    console.print(f"  Size:       {p.size:,} bytes")
    console.print(f"  Machine:    {p.machine}")
    console.print(f"  Subsystem:  {p.subsystem}")
    console.print(f"  Linker:     {p.linker_version}")
    if p.timestamp:
        console.print(f"  Timestamp:  {p.timestamp}")
    if p.signer:
        console.print(f"  Signer:     [green]{p.signer}[/]")

    if p.product_name or p.file_description:
        console.print(f"\n  [bold]Version Info[/]")
        for field_name, val in [
            ("Product", p.product_name), ("Description", p.file_description),
            ("Company", p.company_name), ("Version", p.file_version),
        ]:
            if val:
                console.print(f"    {field_name}: {val}")

    console.print(f"\n  [bold]Framework[/]: [green]{p.framework}[/] ({p.framework_confidence:.0%})")
    if p.framework_evidence:
        console.print(f"    Evidence: {', '.join(p.framework_evidence[:10])}")
    if p.secondary_frameworks:
        console.print(f"    Secondary: {', '.join(p.secondary_frameworks)}")

    console.print(f"\n  [bold]Imports[/]: {p.import_count} total")
    for dll in sorted(p.imports.keys()):
        console.print(f"    {dll}: {len(p.imports[dll])} functions")

    if p.api_categories:
        console.print(f"\n  [bold]API Categories[/]")
        for cat, syms in sorted(p.api_categories.items()):
            console.print(f"    {cat}: {len(syms)} ({', '.join(syms[:5])}{'...' if len(syms) > 5 else ''})")

    if p.device_names:
        console.print(f"\n  [bold]Device Names[/]: {', '.join(p.device_names)}")
    if p.symbolic_links:
        console.print(f"  [bold]Symbolic Links[/]: {', '.join(p.symbolic_links)}")

    if p.sections:
        console.print(f"\n  [bold]Sections[/]")
        for s in p.sections:
            console.print(f"    {s['name']:8s}  vsize={s['virtual_size']:>8,}  raw={s['raw_size']:>8,}  {s['characteristics']}")
    console.print()


def _write_output(path, text):
    with open(path, "w") as f:
        f.write(text)
    console.print(f"[green]Output written to {path}[/]")


@main.command(name="import")
@click.argument("path")
@click.option("-c", "--category", required=True, help="Corpus category (e.g., minifilter, vpn)")
@click.option("-v", "--vendor", required=True, help="Driver vendor name")
@click.option("-d", "--display-name", help="Display name for corpus entry")
@click.option("-s", "--source", help="Source of the driver (e.g., WinBIndex, VirusTotal)")
def import_cmd(path, category, vendor, display_name, source):
    """Import a scanned driver into the corpus."""
    if not os.path.isfile(path):
        console.print(f"[red]File not found:[/] {path}")
        sys.exit(1)

    classifier = _get_classifier()
    cats_path = _CATEGORIES_PATH if os.path.exists(_CATEGORIES_PATH) else None

    try:
        profile = scan_driver(path, classifier=classifier, categories_path=cats_path)
    except Exception as e:
        console.print(f"[red]Scan failed:[/] {e}")
        sys.exit(1)

    corpus = Corpus(_CORPUS_DIR)
    out_path = corpus.import_from_profile(profile, category, vendor, display_name, source)
    console.print(f"[green]Imported {profile.name} → {out_path}[/]")
    console.print(f"  Framework: {profile.framework} ({profile.framework_confidence:.0%})")
    console.print(f"  Imports: {profile.import_count}")


@main.command()
@click.option("--vt-key", envvar="VT_API_KEY", help="VirusTotal API key (or set VT_API_KEY)")
@click.option("--interval", type=int, default=0, help="Re-run interval in seconds (0 = run once)")
@click.option("--min-score", type=float, default=6.0, help="Minimum score to report")
@click.option("--limit", type=int, default=50, help="Max VT results per query")
@click.option("--telegram-token", envvar="TELEGRAM_BOT_TOKEN", help="Telegram bot token")
@click.option("--telegram-chat", envvar="TELEGRAM_CHAT_ID", help="Telegram chat ID")
@click.option("--import-to-corpus", is_flag=True, help="Import high-scoring drivers to corpus")
@click.option("-d", "--directory", type=click.Path(exists=True), help="Scan local directory instead of VT")
def hunt(vt_key, interval, min_score, limit, telegram_token, telegram_chat, import_to_corpus, directory):
    """Hunt for vulnerable drivers (VT Intelligence or local directory)."""
    from .hunter import DriverHunter

    hunter = DriverHunter()

    def _run_once():
        if directory:
            console.print(f"[cyan]Hunting in directory:[/] {directory}")
            results = hunter.hunt_directory(directory, recursive=True, min_score=min_score)
        else:
            if not vt_key:
                console.print("[red]VT_API_KEY required for VT hunting. Use --vt-key or set VT_API_KEY.[/]")
                sys.exit(1)
            os.environ["VT_API_KEY"] = vt_key
            console.print(f"[cyan]Hunting on VirusTotal[/] (limit={limit}, min_score={min_score})")
            results = hunter.hunt_vt(limit=limit, min_score=min_score)

        if not results:
            console.print("[yellow]No findings above threshold.[/]")
            return

        # Print results table
        table = Table(title=f"Hunt Results ({len(results)} drivers)", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Driver", style="cyan")
        table.add_column("Score", justify="right", width=7)
        table.add_column("Risk", width=10)
        table.add_column("SHA256")
        table.add_column("Source")

        for i, r in enumerate(results, 1):
            if r.score.total >= 8.0:
                score_str = f"[bold red]{r.score.total:.1f}[/]"
                risk_str = f"[bold red]{r.score.risk_level}[/]"
            elif r.score.total >= 5.0:
                score_str = f"[yellow]{r.score.total:.1f}[/]"
                risk_str = f"[yellow]{r.score.risk_level}[/]"
            else:
                score_str = f"[green]{r.score.total:.1f}[/]"
                risk_str = f"[green]{r.score.risk_level}[/]"

            table.add_row(str(i), r.name, score_str, risk_str, r.sha256[:16] + "...", r.source)

        console.print(table)

        # Telegram alert
        if telegram_token and telegram_chat:
            sent = hunter.alert_telegram(results, telegram_token, telegram_chat, min_score=8.0)
            if sent:
                console.print("[green]Telegram alert sent.[/]")

    if interval > 0:
        console.print(f"[cyan]Running as daemon (interval={interval}s)[/]")
        while True:
            try:
                _run_once()
                console.print(f"[dim]Sleeping {interval}s...[/]")
                time.sleep(interval)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped.[/]")
                break
    else:
        _run_once()


@main.command()
@click.option("-c", "--category", help="Filter to specific category")
def corpus(category):
    """List corpus entries."""
    c = Corpus(_CORPUS_DIR)

    if category:
        categories = [category]
    else:
        categories = c.list_categories()

    if not categories:
        console.print("[yellow]No corpus categories found.[/]")
        return

    for cat in categories:
        entries = c.list_entries(cat)
        console.print(f"\n[bold cyan]{cat}[/] ({len(entries)} entries)")
        for name in entries:
            entry = c.get_entry(cat, name)
            if entry:
                fw = entry.get("framework", "?")
                vendor = entry.get("vendor", "?")
                console.print(f"  {name}: {fw} ({vendor})")
            else:
                console.print(f"  {name}")
