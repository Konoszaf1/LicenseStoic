"""Tests for the dependency scanner — Layer 1.

Tests importlib.metadata backend, tomllib parsing, deduplication,
npm node_modules enrichment, and SBOM import.
"""

import importlib.metadata
import json
import subprocess
import urllib.error
from email.message import Message
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
    _scan_python_deps,
)


def _make_dist_metadata(
    name: str,
    version: str = "1.0.0",
    license_field: str = "",
    classifiers: list[str] | None = None,
) -> Message:
    """Build an email.message.Message mimicking importlib.metadata dist.metadata."""
    msg = Message()
    msg["Name"] = name
    msg["Version"] = version
    if license_field:
        msg["License"] = license_field
    for c in classifiers or []:
        msg["Classifier"] = c
    return msg


class _FakeDist:
    """Minimal fake for importlib.metadata distribution objects."""

    def __init__(self, metadata: Message) -> None:
        self.metadata = metadata


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
        meta = _make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        mock_distributions.return_value = [_FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"requests"})
        assert len(nodes) == 1
        assert nodes[0].name == "requests"
        assert nodes[0].license_expression.is_valid_spdx
        assert "Apache-2.0" in nodes[0].license_expression.identifiers
        assert nodes[0].confidence == pytest.approx(0.9)

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_falls_back_to_classifiers(self, mock_distributions: object) -> None:
        """Package with UNKNOWN License field but valid classifier."""
        meta = _make_dist_metadata(
            "click",
            "8.1.0",
            license_field="UNKNOWN",
            classifiers=["License :: OSI Approved :: BSD License"],
        )
        mock_distributions.return_value = [_FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"click"})
        assert len(nodes) == 1
        assert nodes[0].confidence == pytest.approx(0.7)
        assert nodes[0].license_expression.is_valid_spdx

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_filters_by_dep_names(self, mock_distributions: object) -> None:
        """Only returns packages in the dep_names set."""
        meta1 = _make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        meta2 = _make_dist_metadata("unrelated", "1.0.0", license_field="MIT")
        mock_distributions.return_value = [  # type: ignore[attr-defined]
            _FakeDist(meta1),
            _FakeDist(meta2),
        ]

        nodes = _scan_importlib_metadata(dep_names={"requests"})
        assert len(nodes) == 1
        assert nodes[0].name == "requests"

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_unknown_stays_unknown(self, mock_distributions: object) -> None:
        """Package with no license info stays UNKNOWN."""
        meta = _make_dist_metadata("mystery", "0.1.0", license_field="")
        mock_distributions.return_value = [_FakeDist(meta)]  # type: ignore[attr-defined]

        nodes = _scan_importlib_metadata(dep_names={"mystery"})
        assert len(nodes) == 1
        assert not nodes[0].license_expression.is_valid_spdx

    @patch("licensestoic.scanner.importlib.metadata.distributions")
    def test_deduplicates_distributions(self, mock_distributions: object) -> None:
        """Multiple dist-info dirs for same package should not produce duplicates."""
        meta1 = _make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        meta2 = _make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        mock_distributions.return_value = [  # type: ignore[attr-defined]
            _FakeDist(meta1),
            _FakeDist(meta2),
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
        requests_meta = _make_dist_metadata("requests", "2.31.0", license_field="Apache-2.0")
        urllib3_meta = _make_dist_metadata("urllib3", "2.0.0", license_field="MIT")
        charset_meta = _make_dist_metadata("charset-normalizer", "3.3.0", license_field="MIT")

        class FakeDistWithRequires:
            def __init__(self, metadata: object, requires: list[str] | None = None) -> None:
                self.metadata = metadata
                self._requires = requires

            @property
            def requires(self) -> list[str] | None:
                return self._requires

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
        mylib_meta = _make_dist_metadata("mylib", "1.0.0", license_field="MIT")
        real_dep_meta = _make_dist_metadata("real-dep", "1.0.0", license_field="MIT")

        class FakeDistWithRequires:
            def __init__(self, metadata: object, requires: list[str] | None = None) -> None:
                self.metadata = metadata
                self._requires = requires

            @property
            def requires(self) -> list[str] | None:
                return self._requires

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
