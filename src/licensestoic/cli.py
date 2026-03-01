"""CLI entry point for LicenseStoic."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click

from licensestoic.git_source import GitCloneError, clone_repo, is_git_url, normalize_git_url
from licensestoic.models import DistributionType
from licensestoic.pipeline import run_pipeline
from licensestoic.report import render_terminal_report, save_json_report


@click.command()
@click.argument("project_source", default=".")
@click.option("--name", "-n", default=None, help="Project name (default: directory or repo name)")
@click.option(
    "--license",
    "-l",
    "project_license",
    default=None,
    help="Project SPDX license (e.g. 'MIT', 'Apache-2.0'). Auto-detected if not specified.",
)
@click.option(
    "--distribution",
    "-d",
    type=click.Choice([t.value for t in DistributionType]),
    default="binary",
    help="How the project is distributed.",
)
@click.option("--ref", default=None, help="Git branch, tag, or commit to checkout (for git URLs)")
@click.option(
    "--sbom", type=click.Path(exists=True), default=None, help="Path to SPDX 2.3 SBOM JSON"
)
@click.option("--scancode/--no-scancode", default=False, help="Use ScanCode for deep scanning")
@click.option(
    "--resolve/--no-resolve",
    default=True,
    help="Auto-install deps into temp venv via uv to resolve unknown licenses",
)
@click.option(
    "--json-report", "-o", type=click.Path(), default=None, help="Save JSON report to file"
)
@click.option(
    "--api-key",
    envvar="ANTHROPIC_API_KEY",
    default=None,
    help="Anthropic API key for LLM explanations",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(
    project_source: str,
    name: str | None,
    project_license: str | None,
    distribution: str,
    ref: str | None,
    sbom: str | None,
    scancode: bool,
    resolve: bool,
    json_report: str | None,
    api_key: str | None,
    verbose: bool,
) -> None:
    """LicenseStoic — Open Source License Self Healer.

    PROJECT_SOURCE can be a local path or a git URL.

    \b
    Examples:
        licensestoic .                                    # scan current directory
        licensestoic /path/to/project                     # scan local project
        licensestoic https://github.com/owner/repo.git    # clone and scan
        licensestoic owner/repo                           # shorthand for GitHub
        licensestoic owner/repo --ref v2.0 --license MIT  # specific tag
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if is_git_url(project_source) or _looks_like_repo_shorthand(project_source):
        _run_on_git_repo(
            project_source,
            name=name,
            project_license=project_license,
            distribution=distribution,
            ref=ref,
            sbom=sbom,
            scancode=scancode,
            resolve=resolve,
            json_report=json_report,
            api_key=api_key,
        )
    else:
        path = Path(project_source).resolve()
        if not path.exists():
            click.echo(f"Error: Path does not exist: {path}", err=True)
            sys.exit(1)
        _run_on_local_path(
            path,
            name=name,
            project_license=project_license,
            distribution=distribution,
            sbom=sbom,
            scancode=scancode,
            resolve=resolve,
            json_report=json_report,
            api_key=api_key,
        )


def _run_on_git_repo(
    source: str,
    *,
    name: str | None,
    project_license: str | None,
    distribution: str,
    ref: str | None,
    sbom: str | None,
    scancode: bool,
    resolve: bool,
    json_report: str | None,
    api_key: str | None,
) -> None:
    """Clone a git repo and scan it."""
    git_url = normalize_git_url(source)
    project_name = name or _repo_name_from_url(git_url)

    try:
        with clone_repo(git_url, ref=ref) as repo_path:
            _run_on_local_path(
                repo_path,
                name=project_name,
                project_license=project_license,
                distribution=distribution,
                sbom=sbom,
                scancode=scancode,
                resolve=resolve,
                json_report=json_report,
                api_key=api_key,
            )
    except GitCloneError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _run_on_local_path(
    path: Path,
    *,
    name: str | None,
    project_license: str | None,
    distribution: str,
    sbom: str | None,
    scancode: bool,
    resolve: bool,
    json_report: str | None,
    api_key: str | None,
) -> None:
    """Run the pipeline on a local directory."""
    project_name = name or path.name

    if not project_license:
        project_license = _detect_project_license(path)
        if not project_license:
            click.echo(
                "Error: Could not detect project license. Use --license to specify.", err=True
            )
            sys.exit(1)

    dist_type = DistributionType(distribution)

    scan_result, explanation = asyncio.run(
        run_pipeline(
            project_path=path,
            project_name=project_name,
            project_license=project_license,
            distribution_type=dist_type,
            use_scancode=scancode,
            resolve_deps=resolve,
            sbom_path=sbom,
            anthropic_api_key=api_key,
        )
    )

    render_terminal_report(scan_result, explanation)

    if json_report:
        out = save_json_report(scan_result, json_report, explanation)
        click.echo(f"JSON report saved to: {out}")

    # Exit code based on conflicts
    if scan_result.conflicts:
        sys.exit(1)
    sys.exit(0)


def _looks_like_repo_shorthand(value: str) -> bool:
    """Check if value looks like 'owner/repo' GitHub shorthand."""
    parts = value.split("/")
    if len(parts) != 2:
        return False
    # Must not look like a local path
    if Path(value).exists():
        return False
    return all(part and not part.startswith(".") for part in parts)


def _repo_name_from_url(url: str) -> str:
    """Extract repository name from a git URL."""
    # https://github.com/owner/repo.git → repo
    name = url.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or "unknown"


def _detect_project_license(path: Path) -> str | None:
    """Try to detect the project license from common files."""
    from licensestoic.parsing import parse_license_expression

    # Check pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("license"):
                # Handle both 'license = "MIT"' and 'license = {text = "MIT"}'
                if "=" in stripped:
                    value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    if value and value != "{":
                        parsed = parse_license_expression(value)
                        if parsed.is_valid_spdx:
                            return value

    # Check package.json
    package_json = path / "package.json"
    if package_json.exists():
        import json

        try:
            with open(package_json) as f:
                pkg = json.load(f)
            lic: str = pkg.get("license", "")
            if lic:
                return lic
        except Exception:
            pass

    # Check LICENSE file content (basic heuristics)
    for license_file in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        lf = path / license_file
        if lf.exists():
            content = lf.read_text(encoding="utf-8", errors="replace").lower()
            if "mit license" in content:
                return "MIT"
            if "apache license" in content and "version 2.0" in content:
                return "Apache-2.0"
            if "gnu general public license" in content:
                if "version 3" in content:
                    return "GPL-3.0-only"
                if "version 2" in content:
                    return "GPL-2.0-only"
            if "bsd 3-clause" in content:
                return "BSD-3-Clause"
            if "bsd 2-clause" in content:
                return "BSD-2-Clause"

    return None


if __name__ == "__main__":
    main()
