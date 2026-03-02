"""Tests for the dependency scanner — Layer 1.

Tests importlib.metadata backend, tomllib parsing, deduplication,
npm node_modules enrichment, SBOM import, npm scanning, and ScanCode.
"""

import importlib.metadata
import json
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from licensestoic.models import DependencyNode, IntegrationType, LicenseExpression
from licensestoic.scanner import (
    _collect_transitive_deps,
    _extract_package_name,
    _lookup_pypi_license,
    _normalize_package_name,
    _parse_pyproject_deps,
    _read_npm_package_license,
    _resolve_via_uv_install,
    _scan_importlib_metadata,
    _scan_npm_deps,
    _scan_python_deps,
    scan_from_sbom,
)

from factories import FakeDist, FakeDistWithRequires, make_dist_metadata


class TestNormalizePackageName:
    """PEP 503 normalization."""

    def test_lowercase(self) -> None:
        assert _normalize_package_name("Pydantic") == "pydantic"

    def test_underscores_to_dashes(self) -> None:
        assert _normalize_package_name("license_expression") == "license-expression"

    def test_dots_to_dashes(self) -> None:
        assert _normalize_package_name("zope.interface") == "zope-interface"

    def test_multiple_separators(self) -> None:
        assert _normalize_package_name("Foo--Bar__Baz") == "foo-bar-baz"


class TestExtractPackageName:
    """PEP 508 dependency string parsing."""

    def test_simple_name(self) -> None:
        assert _extract_package_name("pydantic") == "pydantic"

    def test_with_version_specifier(self) -> None:
        assert _extract_package_name("pydantic>=2.0,<3.0") == "pydantic"

    def test_with_extras(self) -> None:
        assert _extract_package_name("rich[extras]>=13.0") == "rich"

    def test_with_spaces(self) -> None:
        assert _extract_package_name("  click >= 8.0  ") == "click"

    def test_empty_string(self) -> None:
        assert _extract_package_name("") == ""


class TestParsePyprojectDeps:
    """Test tomllib-based pyproject.toml parsing."""

    def test_reads_dependencies(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "myapp"\nversion = "1.0"\n'
            'dependencies = [\n  "pydantic>=2.0",\n  "click>=8.0",\n]\n'
        )
        nodes = _parse_pyproject_deps(pyproject)
        names = {n.name for n in nodes}
        assert "pydantic" in names
        assert "click" in names
        assert all(n.source == "pyproject.toml" for n in nodes)
        assert all(n.confidence == pytest.approx(0.3) for n in nodes)

    def test_empty_dependencies(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "myapp"\nversion = "1.0"\ndependencies = []\n')
        nodes = _parse_pyproject_deps(pyproject)
        assert nodes == []

    def test_no_project_section(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[build-system]\nrequires = ["hatchling"]\n')
        nodes = _parse_pyproject_deps(pyproject)
        assert nodes == []

    def test_malformed_toml(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("this is not valid toml [[[")
        nodes = _parse_pyproject_deps(pyproject)
        assert nodes == []


class TestScanImportlibMetadata:
    """Test the importlib.metadata scanning backend."""

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_finds_installed_package_with_license_field(self, mock_distributions: object) -> None:
        """Package with valid SPDX in License metadata field."""
        meta = make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        mock_distributions.return_value = [FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"requests"})
        assert len(nodes) == 1
        assert nodes[0].name == "requests"
        assert nodes[0].license_expression.is_valid_spdx
        assert "Apache-2.0" in nodes[0].license_expression.identifiers
        assert nodes[0].confidence == pytest.approx(0.9)

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_falls_back_to_classifiers(self, mock_distributions: object) -> None:
        """Package with UNKNOWN License field but valid classifier."""
        meta = make_dist_metadata(
            "click",
            "8.1.0",
            license_field="UNKNOWN",
            classifiers=["License :: OSI Approved :: BSD License"],
        )
        mock_distributions.return_value = [FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"click"})
        assert len(nodes) == 1
        assert nodes[0].confidence == pytest.approx(0.7)
        assert nodes[0].license_expression.is_valid_spdx

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_filters_by_dep_names(self, mock_distributions: object) -> None:
        """Only returns packages in the dep_names set."""
        meta1 = make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        meta2 = make_dist_metadata("unrelated", "1.0.0", license_field="MIT")
        mock_distributions.return_value = [  # type: ignore[attr-defined]
            FakeDist(meta1),
            FakeDist(meta2),
        ]

        nodes = _scan_importlib_metadata(dep_names={"requests"})
        assert len(nodes) == 1
        assert nodes[0].name == "requests"

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_unknown_stays_unknown(self, mock_distributions: object) -> None:
        """Package with no license info stays UNKNOWN."""
        meta = make_dist_metadata("mystery", "0.1.0", license_field="")
        mock_distributions.return_value = [FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"mystery"})
        assert len(nodes) == 1
        assert not nodes[0].license_expression.is_valid_spdx

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_deduplicates_distributions(self, mock_distributions: object) -> None:
        """Multiple dist-info dirs for same package should not produce duplicates."""
        meta1 = make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        meta2 = make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        mock_distributions.return_value = [  # type: ignore[attr-defined]
            FakeDist(meta1),
            FakeDist(meta2),
        ]

        nodes = _scan_importlib_metadata(dep_names={"requests"})
        assert len(nodes) == 1


class TestScanPythonDepsDeduplication:
    """Test that importlib results take priority over pyproject stubs."""

    @patch("licensestoic.scanner._collect_transitive_deps", return_value=[])
    @patch("licensestoic.scanner._scan_importlib_metadata")
    def test_importlib_wins_over_pyproject(
        self, mock_importlib: object, _mock_transitive: object, tmp_path: Path
    ) -> None:
        """If importlib found a package, pyproject stub is not included."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\ndependencies = ["pydantic>=2.0"]\n')

        mock_importlib.return_value = [  # type: ignore[attr-defined]
            DependencyNode(
                name="pydantic",
                version="2.5.0",
                license_expression=LicenseExpression(
                    spdx_expression="MIT",
                    identifiers=["MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="importlib.metadata",
                confidence=0.9,
            )
        ]

        nodes = _scan_python_deps(tmp_path)
        pydantic_nodes = [n for n in nodes if "pydantic" in n.name.lower()]
        assert len(pydantic_nodes) == 1
        assert pydantic_nodes[0].source == "importlib.metadata"
        assert pydantic_nodes[0].confidence == pytest.approx(0.9)


class TestNpmNodeModulesEnrichment:
    """Test reading license from node_modules."""

    def test_reads_license_string(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "express"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({"license": "MIT"}))

        result = _read_npm_package_license(tmp_path, "express")
        assert result == "MIT"

    def test_reads_license_object(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "old-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps({"license": {"type": "ISC", "url": "https://example.com"}})
        )

        result = _read_npm_package_license(tmp_path, "old-pkg")
        assert result == "ISC"

    def test_returns_none_for_missing(self, tmp_path: Path) -> None:
        result = _read_npm_package_license(tmp_path, "nonexistent")
        assert result is None

    def test_returns_none_for_unknown(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "mystery"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({"license": "UNKNOWN"}))

        result = _read_npm_package_license(tmp_path, "mystery")
        assert result is None


def _make_subprocess_result(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestResolveViaUvInstall:
    """Test uv-based dependency resolution into temp venv."""

    @patch("licensestoic.scanner.subprocess.run")
    def test_resolves_unknown_deps(self, mock_run: MagicMock) -> None:
        """Successfully installs deps and reads their license metadata."""
        metadata_json = json.dumps(
            [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "license_expression": "",
                    "license": "Apache-2.0",
                    "classifiers": [],
                },
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "license_expression": "BSD-3-Clause",
                    "license": "",
                    "classifiers": [],
                },
            ]
        )

        # uv venv -> success, uv pip install -> success, python -c -> metadata json
        mock_run.side_effect = [
            _make_subprocess_result(0),  # uv venv
            _make_subprocess_result(0),  # uv pip install
            _make_subprocess_result(0, stdout=metadata_json),  # python -c
        ]

        nodes = _resolve_via_uv_install({"requests", "flask"})
        assert len(nodes) == 2
        names = {n.name for n in nodes}
        assert "requests" in names
        assert "flask" in names

        requests_node = next(n for n in nodes if n.name == "requests")
        assert requests_node.license_expression.is_valid_spdx
        assert requests_node.confidence == pytest.approx(0.9)
        assert requests_node.source == "uv-resolved"

        flask_node = next(n for n in nodes if n.name == "flask")
        assert flask_node.license_expression.is_valid_spdx
        assert flask_node.confidence == pytest.approx(0.95)

    @patch("licensestoic.scanner.subprocess.run")
    def test_filters_to_requested_deps_only(self, mock_run: MagicMock) -> None:
        """Only returns nodes for deps that were requested, not transitive deps."""
        metadata_json = json.dumps(
            [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "license_expression": "",
                    "license": "Apache-2.0",
                    "classifiers": [],
                },
                {
                    "name": "urllib3",
                    "version": "2.0.0",
                    "license_expression": "",
                    "license": "MIT",
                    "classifiers": [],
                },
            ]
        )
        mock_run.side_effect = [
            _make_subprocess_result(0),
            _make_subprocess_result(0),
            _make_subprocess_result(0, stdout=metadata_json),
        ]

        nodes = _resolve_via_uv_install({"requests"})
        assert len(nodes) == 1
        assert nodes[0].name == "requests"

    @patch("licensestoic.scanner.subprocess.run", side_effect=FileNotFoundError)
    def test_graceful_fallback_uv_not_found(self, _mock_run: MagicMock) -> None:
        """Returns empty list when uv is not installed."""
        nodes = _resolve_via_uv_install({"requests"})
        assert nodes == []

    @patch("licensestoic.scanner.subprocess.run")
    def test_graceful_fallback_venv_creation_fails(self, mock_run: MagicMock) -> None:
        """Returns empty list when uv venv fails."""
        mock_run.return_value = _make_subprocess_result(1, stderr="venv error")

        nodes = _resolve_via_uv_install({"requests"})
        assert nodes == []

    @patch("licensestoic.scanner.subprocess.run")
    def test_graceful_fallback_install_fails(self, mock_run: MagicMock) -> None:
        """Returns empty list when uv pip install fails."""
        mock_run.side_effect = [
            _make_subprocess_result(0),  # uv venv ok
            _make_subprocess_result(1, stderr="install error"),  # uv pip install fails
        ]

        nodes = _resolve_via_uv_install({"requests"})
        assert nodes == []

    @patch("licensestoic.scanner.subprocess.run")
    def test_classifier_fallback(self, mock_run: MagicMock) -> None:
        """Falls back to classifier-based resolution."""
        metadata_json = json.dumps(
            [
                {
                    "name": "click",
                    "version": "8.1.0",
                    "license_expression": "",
                    "license": "UNKNOWN",
                    "classifiers": ["License :: OSI Approved :: BSD License"],
                },
            ]
        )
        mock_run.side_effect = [
            _make_subprocess_result(0),
            _make_subprocess_result(0),
            _make_subprocess_result(0, stdout=metadata_json),
        ]

        nodes = _resolve_via_uv_install({"click"})
        assert len(nodes) == 1
        assert nodes[0].license_expression.is_valid_spdx
        assert nodes[0].confidence == pytest.approx(0.7)


class TestScanPythonDepsUvResolution:
    """Test that _scan_python_deps triggers uv resolution for UNKNOWN deps."""

    @patch("licensestoic.scanner._collect_transitive_deps", return_value=[])
    @patch("licensestoic.scanner._resolve_via_uv_install")
    @patch("licensestoic.scanner._scan_importlib_metadata")
    def test_no_resolution_when_all_known(
        self,
        mock_importlib: MagicMock,
        mock_resolve: MagicMock,
        _mock_transitive: MagicMock,
        tmp_path: Path,
    ) -> None:
        """No uv resolution when importlib resolved everything."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "t"\ndependencies = ["pydantic>=2.0"]\n')

        mock_importlib.return_value = [
            DependencyNode(
                name="pydantic",
                version="2.5.0",
                license_expression=LicenseExpression(
                    spdx_expression="MIT", identifiers=["MIT"], is_valid_spdx=True
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="importlib.metadata",
                confidence=0.9,
            )
        ]

        _scan_python_deps(tmp_path, resolve_deps=True)
        mock_resolve.assert_not_called()

    @patch("licensestoic.scanner._collect_transitive_deps", return_value=[])
    @patch("licensestoic.scanner._resolve_via_uv_install")
    @patch("licensestoic.scanner._scan_importlib_metadata")
    def test_resolution_triggered_for_unknown(
        self,
        mock_importlib: MagicMock,
        mock_resolve: MagicMock,
        _mock_transitive: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Triggers uv resolution when deps are UNKNOWN."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "t"\ndependencies = ["requests>=2.0"]\n')

        mock_importlib.return_value = []
        mock_resolve.return_value = [
            DependencyNode(
                name="requests",
                version="2.31.0",
                license_expression=LicenseExpression(
                    spdx_expression="Apache-2.0",
                    identifiers=["Apache-2.0"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="uv-resolved",
                confidence=0.9,
            )
        ]

        nodes = _scan_python_deps(tmp_path, resolve_deps=True)
        mock_resolve.assert_called_once()
        requests_node = next(n for n in nodes if n.name == "requests")
        assert requests_node.source == "uv-resolved"
        assert requests_node.confidence == pytest.approx(0.9)

    @patch("licensestoic.scanner._collect_transitive_deps", return_value=[])
    @patch("licensestoic.scanner._resolve_via_uv_install")
    @patch("licensestoic.scanner._scan_importlib_metadata")
    def test_resolution_skipped_when_disabled(
        self,
        mock_importlib: MagicMock,
        mock_resolve: MagicMock,
        _mock_transitive: MagicMock,
        tmp_path: Path,
    ) -> None:
        """No uv resolution when resolve_deps=False."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "t"\ndependencies = ["requests>=2.0"]\n')

        mock_importlib.return_value = []

        _scan_python_deps(tmp_path, resolve_deps=False)
        mock_resolve.assert_not_called()


# ---------------------------------------------------------------------------
# Bug 2: PyPI JSON API fallback
# ---------------------------------------------------------------------------


class TestPypiApiLookup:
    """Test the PyPI JSON API fallback for unresolved licenses."""

    @patch("licensestoic.scanner.urllib.request.urlopen")
    def test_resolves_mit_from_license_field(self, mock_urlopen: MagicMock) -> None:
        """PyPI API returns MIT from the license field."""
        pypi_response = json.dumps(
            {
                "info": {
                    "license": "MIT",
                    "classifiers": [],
                }
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = pypi_response
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        spdx_id, confidence = _lookup_pypi_license("tiktoken")
        assert spdx_id == "MIT"
        assert confidence >= 0.7

    @patch("licensestoic.scanner.urllib.request.urlopen")
    def test_resolves_from_classifier(self, mock_urlopen: MagicMock) -> None:
        """PyPI API falls back to classifiers."""
        pypi_response = json.dumps(
            {
                "info": {
                    "license": "",
                    "classifiers": [
                        "License :: OSI Approved :: Apache Software License",
                    ],
                }
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = pypi_response
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        spdx_id, confidence = _lookup_pypi_license("some-package")
        assert spdx_id == "Apache-2.0"
        assert confidence >= 0.5

    @patch(
        "licensestoic.scanner.urllib.request.urlopen",
        side_effect=urllib.error.URLError("network error"),
    )
    def test_graceful_failure(self, _mock: MagicMock) -> None:
        """Returns (None, 0.0) on network error."""
        spdx_id, confidence = _lookup_pypi_license("nonexistent")
        assert spdx_id is None
        assert confidence == 0.0


# ---------------------------------------------------------------------------
# Bug 4: Transitive dependency scanning
# ---------------------------------------------------------------------------


class TestTransitiveDependencyCollection:
    """Test that transitive deps are collected via importlib.metadata requires."""

    @patch("licensestoic.scanner.importlib.metadata.distribution")
    def test_collects_transitive_deps(self, mock_dist_fn: MagicMock) -> None:
        """requests -> urllib3 -> charset-normalizer chain is discovered."""
        # Build fake distribution objects
        requests_meta = make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        urllib3_meta = make_dist_metadata("urllib3", "2.0.0", license_field="MIT")
        charset_meta = make_dist_metadata("charset-normalizer", "3.3.0", license_field="MIT")

        requests_dist = FakeDistWithRequires(requests_meta, ["urllib3>=2.0"])
        urllib3_dist = FakeDistWithRequires(urllib3_meta, ["charset-normalizer>=3.0"])
        charset_dist = FakeDistWithRequires(charset_meta, None)

        def dist_side_effect(name: str) -> object:
            mapping = {
                "requests": requests_dist,
                "urllib3": urllib3_dist,
                "charset-normalizer": charset_dist,
            }
            if name in mapping:
                return mapping[name]
            raise importlib.metadata.PackageNotFoundError(name)

        mock_dist_fn.side_effect = dist_side_effect

        result = _collect_transitive_deps(
            direct_names={"requests"},
            existing_names={"requests"},
        )

        names = {n.name for n in result}
        assert "urllib3" in names
        assert "charset-normalizer" in names
        assert all(n.depth >= 2 for n in result)

    @patch("licensestoic.scanner.importlib.metadata.distribution")
    def test_skips_extras_only_deps(self, mock_dist_fn: MagicMock) -> None:
        """Dependencies with 'extra ==' markers are skipped."""
        mylib_meta = make_dist_metadata("mylib", "1.0.0", license_field="MIT")
        real_dep_meta = make_dist_metadata("real-dep", "1.0.0", license_field="MIT")

        mylib_dist = FakeDistWithRequires(
            mylib_meta, ['optional-dep>=1.0 ; extra == "dev"', "real-dep>=1.0"]
        )
        real_dep_dist = FakeDistWithRequires(real_dep_meta, None)

        def dist_side_effect(name: str) -> object:
            if name == "mylib":
                return mylib_dist
            if name == "real-dep":
                return real_dep_dist
            raise importlib.metadata.PackageNotFoundError(name)

        mock_dist_fn.side_effect = dist_side_effect

        result = _collect_transitive_deps(
            direct_names={"mylib"},
            existing_names={"mylib"},
        )

        names = {n.name for n in result}
        assert "optional-dep" not in names
        assert "real-dep" in names


# ---------------------------------------------------------------------------
# SBOM import tests
# ---------------------------------------------------------------------------


class TestScanFromSbom:
    """Test SPDX 2.3 SBOM JSON import."""

    def test_valid_sbom_with_packages(self, tmp_path: Path) -> None:
        sbom = {
            "packages": [
                {
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "licenseDeclared": "Apache-2.0",
                },
                {
                    "name": "click",
                    "versionInfo": "8.1.0",
                    "licenseDeclared": "BSD-3-Clause",
                },
            ]
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))

        nodes = scan_from_sbom(sbom_file)
        assert len(nodes) == 2
        names = {n.name for n in nodes}
        assert "requests" in names
        assert "click" in names
        assert all(n.source == "spdx_sbom" for n in nodes)

    def test_noassertion_packages_skipped(self, tmp_path: Path) -> None:
        sbom = {
            "packages": [
                {"name": "unknown-pkg", "licenseDeclared": "NOASSERTION"},
                {"name": "known-pkg", "licenseDeclared": "MIT"},
            ]
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))

        nodes = scan_from_sbom(sbom_file)
        assert len(nodes) == 1
        assert nodes[0].name == "known-pkg"

    def test_empty_packages_list(self, tmp_path: Path) -> None:
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"packages": []}))

        nodes = scan_from_sbom(sbom_file)
        assert nodes == []

    def test_missing_packages_key(self, tmp_path: Path) -> None:
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))

        nodes = scan_from_sbom(sbom_file)
        assert nodes == []

    def test_package_without_version(self, tmp_path: Path) -> None:
        sbom = {"packages": [{"name": "pkg", "licenseDeclared": "MIT"}]}
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))

        nodes = scan_from_sbom(sbom_file)
        assert len(nodes) == 1
        assert nodes[0].version is None


# ---------------------------------------------------------------------------
# npm scanning pipeline tests
# ---------------------------------------------------------------------------


class TestScanNpmDeps:
    """Test the full npm dependency scanning pipeline."""

    def test_no_package_json_returns_empty(self, tmp_path: Path) -> None:
        nodes = _scan_npm_deps(tmp_path)
        assert nodes == []

    def test_reads_direct_deps_from_package_json(self, tmp_path: Path) -> None:
        """When npm ls is not available, falls back to package.json + node_modules."""
        pkg = {
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        # Create node_modules with license info
        express_dir = tmp_path / "node_modules" / "express"
        express_dir.mkdir(parents=True)
        (express_dir / "package.json").write_text(json.dumps({"license": "MIT"}))

        jest_dir = tmp_path / "node_modules" / "jest"
        jest_dir.mkdir(parents=True)
        (jest_dir / "package.json").write_text(json.dumps({"license": "MIT"}))

        with patch("licensestoic.scanner.subprocess.run", side_effect=FileNotFoundError):
            nodes = _scan_npm_deps(tmp_path)

        assert len(nodes) == 2
        express_node = next(n for n in nodes if n.name == "express")
        assert express_node.license_expression.is_valid_spdx
        assert express_node.integration_type == IntegrationType.STATIC_LINK

        jest_node = next(n for n in nodes if n.name == "jest")
        assert jest_node.integration_type == IntegrationType.DEV_ONLY

    def test_dev_deps_marked_correctly(self, tmp_path: Path) -> None:
        pkg = {"devDependencies": {"prettier": "^3.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        with patch("licensestoic.scanner.subprocess.run", side_effect=FileNotFoundError):
            nodes = _scan_npm_deps(tmp_path)

        assert len(nodes) == 1
        assert nodes[0].integration_type == IntegrationType.DEV_ONLY

    @patch("licensestoic.scanner.subprocess.run")
    def test_npm_ls_tree_walking(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """When npm ls succeeds, walk the full tree."""
        npm_tree = {
            "dependencies": {
                "express": {
                    "version": "4.18.0",
                    "dependencies": {
                        "body-parser": {"version": "1.20.0"},
                    },
                },
            }
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(npm_tree), stderr=""
        )

        pkg = {"dependencies": {"express": "^4.18.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        # Create node_modules for enrichment
        for name in ("express", "body-parser"):
            d = tmp_path / "node_modules" / name
            d.mkdir(parents=True)
            (d / "package.json").write_text(json.dumps({"license": "MIT"}))

        nodes = _scan_npm_deps(tmp_path)
        names = {n.name for n in nodes}
        assert "express" in names
        assert "body-parser" in names

        bp = next(n for n in nodes if n.name == "body-parser")
        assert bp.depth == 2
        assert bp.parent == "express"

    def test_malformed_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("not valid json {{{")
        nodes = _scan_npm_deps(tmp_path)
        assert nodes == []
