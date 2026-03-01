"""License scanning adapter — Layer 1.

Provides multiple scanning backends:
1. importlib.metadata (stdlib — scans installed packages for real license data)
2. Package metadata scanning (reads pyproject.toml / package.json / etc.)
3. ScanCode Toolkit (full file-level scanning, optional heavy dependency)

The scanner produces DependencyNode objects that feed into the validator.
"""

from __future__ import annotations

import importlib.metadata
import json
import logging
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import urllib.error
from pathlib import Path

from licensestoic.models import DependencyNode, IntegrationType
from licensestoic.parsing import parse_license_expression

logger = logging.getLogger(__name__)

# Classifier → SPDX mapping for the most common OSI-approved licenses.
# Used when a package's License metadata field is missing or unhelpful.
_CLASSIFIER_TO_SPDX: dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Artistic License": "Artistic-2.0",
    "License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}


def scan_directory(
    path: str | Path, use_scancode: bool = False, resolve_deps: bool = True
) -> list[DependencyNode]:
    """Scan a project directory for dependency licenses.

    Args:
        path: Root directory of the project to scan.
        use_scancode: If True, use ScanCode Toolkit for deep scanning.
                      Requires scancode-toolkit to be installed.
        resolve_deps: If True, auto-install unresolved deps into a temp venv
                      via ``uv`` to read their real license metadata.
    """
    project_path = Path(path)
    nodes: list[DependencyNode] = []

    # Scan package manager manifests
    nodes.extend(_scan_python_deps(project_path, resolve_deps=resolve_deps))
    nodes.extend(_scan_npm_deps(project_path))

    if use_scancode:
        nodes.extend(_scan_with_scancode(project_path))

    return nodes


def scan_from_sbom(sbom_path: str | Path) -> list[DependencyNode]:
    """Import dependencies from an existing SPDX 2.3 JSON SBOM."""
    sbom_path = Path(sbom_path)
    with open(sbom_path) as f:
        sbom = json.load(f)

    nodes: list[DependencyNode] = []
    for package in sbom.get("packages", []):
        license_declared = package.get("licenseDeclared", "NOASSERTION")
        if license_declared == "NOASSERTION":
            continue

        name = package.get("name", "unknown")
        version = package.get("versionInfo")

        nodes.append(
            DependencyNode(
                name=name,
                version=version,
                license_expression=parse_license_expression(license_declared),
                integration_type=IntegrationType.STATIC_LINK,  # default; user should refine
                depth=1,
                source="spdx_sbom",
            )
        )

    return nodes


def _normalize_package_name(name: str) -> str:
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_package_name(dep_str: str) -> str:
    """Extract package name from a PEP 508 dependency string.

    E.g. 'pydantic>=2.0,<3.0' -> 'pydantic'
         'rich[extras]>=13.0' -> 'rich'
    """
    match = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)", dep_str.strip())
    return match.group(1) if match else ""


def _scan_python_deps(project_path: Path, *, resolve_deps: bool = True) -> list[DependencyNode]:
    """Extract license info from Python packages.

    Scanning priority:
    1. importlib.metadata (installed packages with real licenses)
    2. pyproject.toml via tomllib (names only, for deps not installed yet)
    3. Deduplicate: importlib-found packages take priority over pyproject stubs
    4. If resolve_deps is True, install still-UNKNOWN deps into a temp venv
       via uv and collect their real license metadata.
    """
    # Step 1: Parse pyproject.toml to get declared dependency names
    pyproject = project_path / "pyproject.toml"
    pyproject_nodes: list[DependencyNode] = []

    if pyproject.exists():
        pyproject_nodes = _parse_pyproject_deps(pyproject)

    declared_dep_names = {_normalize_package_name(n.name) for n in pyproject_nodes}

    # Step 2: Scan importlib.metadata for installed packages
    # Filter to only dependencies declared in pyproject.toml (if available)
    if declared_dep_names:
        importlib_nodes = _scan_importlib_metadata(dep_names=declared_dep_names)
    else:
        importlib_nodes = []

    # Step 3: Deduplicate — importlib results take priority
    importlib_found = {_normalize_package_name(n.name) for n in importlib_nodes}
    nodes: list[DependencyNode] = list(importlib_nodes)

    # Add pyproject.toml deps that importlib didn't find
    for node in pyproject_nodes:
        if _normalize_package_name(node.name) not in importlib_found:
            nodes.append(node)

    # Step 4: Resolve still-UNKNOWN deps via uv temp venv
    if resolve_deps:
        unknown_names = {
            _normalize_package_name(n.name)
            for n in nodes
            if n.license_expression.spdx_expression.upper() in ("UNKNOWN", "")
        }
        if unknown_names:
            logger.info("Resolving %d unknown deps via uv install...", len(unknown_names))
            resolved = _resolve_via_uv_install(unknown_names)
            if resolved:
                resolved_map = {_normalize_package_name(n.name): n for n in resolved}
                nodes = [resolved_map.pop(_normalize_package_name(n.name), n) for n in nodes]

    # Step 5: PyPI JSON API fallback for any remaining UNKNOWN deps
    still_unknown = [
        n for n in nodes if n.license_expression.spdx_expression.upper() in ("UNKNOWN", "")
    ]
    for node in still_unknown:
        spdx_id, confidence = _lookup_pypi_license(node.name)
        if spdx_id:
            idx = nodes.index(node)
            nodes[idx] = DependencyNode(
                name=node.name,
                version=node.version,
                license_expression=parse_license_expression(spdx_id),
                integration_type=node.integration_type,
                depth=node.depth,
                parent=node.parent,
                source="pypi-api",
                confidence=confidence,
            )

    # Step 6: Collect transitive dependencies
    existing_names = {_normalize_package_name(n.name) for n in nodes}
    transitive_nodes = _collect_transitive_deps(declared_dep_names, existing_names)
    if transitive_nodes:
        logger.info("Found %d transitive dependencies", len(transitive_nodes))
    nodes.extend(transitive_nodes)

    return nodes


def _scan_importlib_metadata(
    dep_names: set[str] | None = None,
) -> list[DependencyNode]:
    """Scan installed packages via importlib.metadata (stdlib).

    If dep_names is provided, only return results for those packages.
    Otherwise scan all installed packages.
    """
    nodes: list[DependencyNode] = []
    seen: set[str] = set()

    for dist in importlib.metadata.distributions():
        dist_name = dist.metadata.get("Name", "")
        if not dist_name:
            continue

        normalized = _normalize_package_name(dist_name)

        # Skip duplicates (multiple .dist-info dirs can exist)
        if normalized in seen:
            continue
        seen.add(normalized)

        # If filtering, skip packages not in the target set
        if dep_names is not None and normalized not in dep_names:
            continue

        version = dist.metadata.get("Version", "")

        # Strategy 1: Try PEP 639 License-Expression field (highest authority)
        license_expr_field = (dist.metadata.get("License-Expression") or "").strip()
        spdx_id: str | None = None
        confidence = 0.3

        if license_expr_field:
            parsed = parse_license_expression(license_expr_field)
            if parsed.is_valid_spdx:
                spdx_id = parsed.spdx_expression
                confidence = 0.95

        # Strategy 2: Try legacy License metadata field
        if spdx_id is None:
            license_str = (dist.metadata.get("License") or "").strip()
            if license_str and license_str.upper() not in ("UNKNOWN", ""):
                parsed = parse_license_expression(license_str)
                if parsed.is_valid_spdx:
                    spdx_id = parsed.spdx_expression
                    confidence = 0.9

        # Strategy 3: If no valid SPDX from License fields, try classifiers
        if spdx_id is None:
            classifiers = dist.metadata.get_all("Classifier") or []
            for classifier in classifiers:
                if classifier in _CLASSIFIER_TO_SPDX:
                    spdx_id = _CLASSIFIER_TO_SPDX[classifier]
                    confidence = 0.7
                    break

        # Build the license expression
        if spdx_id:
            license_expr = parse_license_expression(spdx_id)
        else:
            license_expr = parse_license_expression("UNKNOWN")

        nodes.append(
            DependencyNode(
                name=dist_name,
                version=version or None,
                license_expression=license_expr,
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="importlib.metadata",
                confidence=confidence,
            )
        )

    return nodes


def _parse_pyproject_deps(pyproject_path: Path) -> list[DependencyNode]:
    """Extract dependency names from pyproject.toml using stdlib tomllib."""
    nodes: list[DependencyNode] = []
    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        dependencies: list[str] = data.get("project", {}).get("dependencies", [])
        for dep_str in dependencies:
            name = _extract_package_name(dep_str)
            if name:
                nodes.append(
                    DependencyNode(
                        name=name,
                        version=None,
                        license_expression=parse_license_expression("UNKNOWN"),
                        integration_type=IntegrationType.STATIC_LINK,
                        depth=1,
                        source="pyproject.toml",
                        confidence=0.3,
                    )
                )
    except Exception:
        logger.debug("Failed to parse %s", pyproject_path, exc_info=True)

    return nodes


# Inline script executed inside the temp venv to collect package metadata.
# Kept minimal — only stdlib imports so it works in a bare venv.
_METADATA_COLLECTOR_SCRIPT = """\
import importlib.metadata, json
results = []
for d in importlib.metadata.distributions():
    name = d.metadata.get("Name", "")
    if not name:
        continue
    results.append({
        "name": name,
        "version": d.metadata.get("Version", ""),
        "license_expression": d.metadata.get("License-Expression", ""),
        "license": d.metadata.get("License", ""),
        "classifiers": d.metadata.get_all("Classifier") or [],
    })
print(json.dumps(results))
"""


def _resolve_via_uv_install(dep_names: set[str]) -> list[DependencyNode]:
    """Install packages into a temp venv via uv and read their license metadata.

    Returns DependencyNode list for every successfully resolved package.
    On any failure (uv missing, install error, etc.) returns [].
    """
    nodes: list[DependencyNode] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix="licensestoic-resolve-", ignore_cleanup_errors=True
        ) as tmp_dir:
            venv_path = Path(tmp_dir) / "venv"

            # Create temp venv
            proc = subprocess.run(
                ["uv", "venv", str(venv_path), "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                logger.warning("uv venv creation failed: %s", proc.stderr[:300])
                return []

            # Determine venv Python path (Windows vs Unix)
            if sys.platform == "win32":
                venv_python = str(venv_path / "Scripts" / "python.exe")
            else:
                venv_python = str(venv_path / "bin" / "python")

            # Install all deps in one shot (uv parallelises natively)
            install_cmd = [
                "uv",
                "pip",
                "install",
                "--quiet",
                "--python",
                venv_python,
                *sorted(dep_names),
            ]
            logger.info("Installing deps: %s", " ".join(sorted(dep_names)))
            proc = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning("uv pip install failed: %s", proc.stderr[:500])
                return []

            # Collect metadata from inside the venv
            proc = subprocess.run(
                [venv_python, "-c", _METADATA_COLLECTOR_SCRIPT],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                logger.warning("Metadata collection failed: %s", proc.stderr[:300])
                return []

            raw_results: list[dict[str, object]] = json.loads(proc.stdout)

            # Build DependencyNode objects using the same resolution logic
            for pkg in raw_results:
                name = str(pkg.get("name", ""))
                if not name:
                    continue
                normalized = _normalize_package_name(name)
                if normalized not in dep_names:
                    continue

                version = str(pkg.get("version", ""))
                spdx_id: str | None = None
                confidence = 0.3

                # PEP 639 License-Expression (highest authority)
                license_expr_field = str(pkg.get("license_expression", "")).strip()
                if license_expr_field:
                    parsed = parse_license_expression(license_expr_field)
                    if parsed.is_valid_spdx:
                        spdx_id = parsed.spdx_expression
                        confidence = 0.95

                # Legacy License field
                if spdx_id is None:
                    license_str = str(pkg.get("license", "")).strip()
                    if license_str and license_str.upper() not in ("UNKNOWN", ""):
                        parsed = parse_license_expression(license_str)
                        if parsed.is_valid_spdx:
                            spdx_id = parsed.spdx_expression
                            confidence = 0.9

                # Classifiers
                if spdx_id is None:
                    classifiers = pkg.get("classifiers", [])
                    if isinstance(classifiers, list):
                        for classifier in classifiers:
                            if isinstance(classifier, str) and classifier in _CLASSIFIER_TO_SPDX:
                                spdx_id = _CLASSIFIER_TO_SPDX[classifier]
                                confidence = 0.7
                                break

                if spdx_id:
                    license_expr = parse_license_expression(spdx_id)
                else:
                    license_expr = parse_license_expression("UNKNOWN")

                nodes.append(
                    DependencyNode(
                        name=name,
                        version=version or None,
                        license_expression=license_expr,
                        integration_type=IntegrationType.STATIC_LINK,
                        depth=1,
                        source="uv-resolved",
                        confidence=confidence,
                    )
                )

    except FileNotFoundError:
        logger.info("uv not found on PATH — skipping dependency resolution")
    except subprocess.TimeoutExpired:
        logger.warning("Dependency resolution timed out")
    except Exception:
        logger.debug("Dependency resolution failed", exc_info=True)

    return nodes


def _lookup_pypi_license(package_name: str) -> tuple[str | None, float]:
    """Look up a package's license via the PyPI JSON API.

    Returns (spdx_id_or_None, confidence).
    This is a last-resort fallback when importlib.metadata and uv resolution
    both fail to resolve a license.
    """
    normalized = _normalize_package_name(package_name)
    url = f"https://pypi.org/pypi/{normalized}/json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        info = data.get("info", {})

        # Priority 1: License-Expression (PEP 639) — not yet widely used on PyPI
        # but future-proof
        license_expr = (info.get("license_expression") or "").strip()
        if license_expr and license_expr.upper() not in ("UNKNOWN", ""):
            parsed = parse_license_expression(license_expr)
            if parsed.is_valid_spdx:
                logger.info("PyPI API resolved %s -> %s (PEP 639)", package_name, license_expr)
                return parsed.spdx_expression, 0.85

        # Priority 2: Legacy license field
        license_str = (info.get("license") or "").strip()
        if license_str and license_str.upper() not in ("UNKNOWN", ""):
            parsed = parse_license_expression(license_str)
            if parsed.is_valid_spdx:
                logger.info("PyPI API resolved %s -> %s (license field)", package_name, license_str)
                return parsed.spdx_expression, 0.8

        # Priority 3: Classifiers
        classifiers = info.get("classifiers") or []
        for classifier in classifiers:
            if isinstance(classifier, str) and classifier in _CLASSIFIER_TO_SPDX:
                spdx = _CLASSIFIER_TO_SPDX[classifier]
                logger.info("PyPI API resolved %s -> %s (classifier)", package_name, spdx)
                return spdx, 0.65

    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        logger.debug("PyPI API lookup failed for %s", package_name, exc_info=True)

    return None, 0.0


def _collect_transitive_deps(
    direct_names: set[str],
    existing_names: set[str],
) -> list[DependencyNode]:
    """Walk importlib.metadata requires() to discover transitive dependencies.

    Returns DependencyNode objects for packages that are installed but NOT
    in the direct dependency set (i.e. they are transitive).
    """
    transitive_nodes: list[DependencyNode] = []
    visited: set[str] = set(existing_names)
    queue: list[tuple[str, str | None, int]] = [(name, None, 1) for name in direct_names]

    while queue:
        name, parent, depth = queue.pop(0)
        try:
            dist = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            # Try alternate normalization (underscore vs dash)
            alt = name.replace("-", "_")
            try:
                dist = importlib.metadata.distribution(alt)
            except importlib.metadata.PackageNotFoundError:
                continue

        requires = dist.requires or []
        for req_str in requires:
            # Skip extras-only requirements (e.g. 'foo ; extra == "dev"')
            if "extra ==" in req_str or "extra==" in req_str:
                continue
            req_name = _extract_package_name(req_str)
            if not req_name:
                continue
            normalized = _normalize_package_name(req_name)
            if normalized in visited:
                continue
            visited.add(normalized)

            # Build a DependencyNode for this transitive dep
            node = _scan_single_installed_package(normalized, parent=name, depth=depth + 1)
            if node is not None:
                transitive_nodes.append(node)
                queue.append((normalized, name, depth + 1))

    return transitive_nodes


def _scan_single_installed_package(
    normalized_name: str,
    parent: str | None = None,
    depth: int = 2,
) -> DependencyNode | None:
    """Scan a single installed package via importlib.metadata.

    Returns None if the package is not installed.
    """
    try:
        dist = importlib.metadata.distribution(normalized_name)
    except importlib.metadata.PackageNotFoundError:
        alt = normalized_name.replace("-", "_")
        try:
            dist = importlib.metadata.distribution(alt)
        except importlib.metadata.PackageNotFoundError:
            return None

    dist_name = dist.metadata.get("Name", normalized_name)
    version = dist.metadata.get("Version", "")

    spdx_id: str | None = None
    confidence = 0.3

    # PEP 639
    license_expr_field = (dist.metadata.get("License-Expression") or "").strip()
    if license_expr_field:
        parsed = parse_license_expression(license_expr_field)
        if parsed.is_valid_spdx:
            spdx_id = parsed.spdx_expression
            confidence = 0.95

    # Legacy License field
    if spdx_id is None:
        license_str = (dist.metadata.get("License") or "").strip()
        if license_str and license_str.upper() not in ("UNKNOWN", ""):
            parsed = parse_license_expression(license_str)
            if parsed.is_valid_spdx:
                spdx_id = parsed.spdx_expression
                confidence = 0.9

    # Classifiers
    if spdx_id is None:
        classifiers = dist.metadata.get_all("Classifier") or []
        for classifier in classifiers:
            if classifier in _CLASSIFIER_TO_SPDX:
                spdx_id = _CLASSIFIER_TO_SPDX[classifier]
                confidence = 0.7
                break

    if spdx_id:
        license_expr = parse_license_expression(spdx_id)
    else:
        license_expr = parse_license_expression("UNKNOWN")

    return DependencyNode(
        name=dist_name,
        version=version or None,
        license_expression=license_expr,
        integration_type=IntegrationType.STATIC_LINK,
        depth=depth,
        parent=parent,
        source="importlib.metadata",
        confidence=confidence,
    )


def _scan_npm_deps(project_path: Path) -> list[DependencyNode]:
    """Extract license info from npm package.json."""
    package_json = project_path / "package.json"
    if not package_json.exists():
        return []

    nodes: list[DependencyNode] = []
    try:
        with open(package_json, encoding="utf-8", errors="replace") as f:
            pkg = json.load(f)

        # Try npm ls for full dependency tree with licenses
        try:
            proc = subprocess.run(
                ["npm", "ls", "--json", "--all"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(project_path),
            )
            if proc.returncode == 0:
                tree = json.loads(proc.stdout)
                _walk_npm_tree(
                    tree.get("dependencies", {}),
                    nodes,
                    depth=1,
                    project_path=project_path,
                )
                return nodes
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: read direct dependencies from package.json + enrich from node_modules
        for dep_name in pkg.get("dependencies", {}):
            license_str = "UNKNOWN"
            confidence = 0.3
            source = "package.json"

            nm_license = _read_npm_package_license(project_path, dep_name)
            if nm_license:
                license_str = nm_license
                confidence = 0.8
                source = "node_modules/package.json"

            nodes.append(
                DependencyNode(
                    name=dep_name,
                    version=pkg["dependencies"][dep_name],
                    license_expression=parse_license_expression(license_str),
                    integration_type=IntegrationType.STATIC_LINK,
                    depth=1,
                    source=source,
                    confidence=confidence,
                )
            )

        for dep_name in pkg.get("devDependencies", {}):
            license_str = "UNKNOWN"
            confidence = 0.3
            source = "package.json"

            nm_license = _read_npm_package_license(project_path, dep_name)
            if nm_license:
                license_str = nm_license
                confidence = 0.8
                source = "node_modules/package.json"

            nodes.append(
                DependencyNode(
                    name=dep_name,
                    version=pkg["devDependencies"][dep_name],
                    license_expression=parse_license_expression(license_str),
                    integration_type=IntegrationType.DEV_ONLY,
                    depth=1,
                    source=source,
                    confidence=confidence,
                )
            )

    except Exception:
        logger.debug("Failed to parse %s", package_json, exc_info=True)

    return nodes


def _read_npm_package_license(project_path: Path, package_name: str) -> str | None:
    """Read the license field from node_modules/{name}/package.json."""
    pkg_json = project_path / "node_modules" / package_name / "package.json"
    if not pkg_json.exists():
        return None
    try:
        with open(pkg_json, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        license_val = data.get("license", "")
        if isinstance(license_val, str) and license_val and license_val.upper() != "UNKNOWN":
            return license_val
        # Handle {"type": "MIT", "url": "..."} legacy form
        if isinstance(license_val, dict):
            ltype = license_val.get("type")
            if isinstance(ltype, str):
                return ltype
    except Exception:
        pass
    return None


def _walk_npm_tree(
    deps: dict[str, dict[str, object]],
    nodes: list[DependencyNode],
    depth: int,
    project_path: Path,
    parent: str | None = None,
) -> None:
    """Recursively walk npm dependency tree."""
    for name, info in deps.items():
        version = info.get("version", "")
        license_str = "UNKNOWN"
        confidence = 0.3
        source = "npm-ls"

        # Enrich from node_modules
        nm_license = _read_npm_package_license(project_path, name)
        if nm_license:
            license_str = nm_license
            confidence = 0.8
            source = "node_modules/package.json"

        nodes.append(
            DependencyNode(
                name=name,
                version=version if isinstance(version, str) else None,
                license_expression=parse_license_expression(license_str),
                integration_type=IntegrationType.STATIC_LINK,
                depth=depth,
                parent=parent,
                source=source,
                confidence=confidence,
            )
        )
        sub_deps = info.get("dependencies")
        if isinstance(sub_deps, dict):
            _walk_npm_tree(
                sub_deps,
                nodes,
                depth=depth + 1,
                project_path=project_path,
                parent=name,
            )


def _scan_with_scancode(project_path: Path) -> list[DependencyNode]:
    """Run ScanCode Toolkit for deep file-level license scanning."""
    nodes: list[DependencyNode] = []
    try:
        proc = subprocess.run(
            [
                "scancode",
                "--license",
                "--copyright",
                "--package",
                "--json-pp",
                "-",
                "--quiet",
                str(project_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            logger.warning("ScanCode failed: %s", proc.stderr[:500])
            return nodes

        data = json.loads(proc.stdout)
        for file_result in data.get("files", []):
            licenses = file_result.get("license_expressions", [])
            if not licenses:
                continue
            for lic_expr in licenses:
                nodes.append(
                    DependencyNode(
                        name=file_result.get("path", "unknown"),
                        version=None,
                        license_expression=parse_license_expression(lic_expr),
                        integration_type=IntegrationType.STATIC_LINK,
                        depth=0,
                        source="scancode",
                        confidence=file_result.get("percentage_of_license_text", 50.0) / 100.0,
                    )
                )

    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        logger.warning("ScanCode not available or timed out", exc_info=True)

    return nodes
