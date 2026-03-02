"""Tests for the CLI entry point.

Covers:
- Click argument parsing and help output
- License auto-detection from pyproject.toml, package.json, LICENSE files
- Exit codes (0 for clean, 1 for conflicts or errors)
- Git URL vs local path routing
- Error handling for missing paths
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from licensestoic.cli import (
    _detect_project_license,
    _looks_like_repo_shorthand,
    _repo_name_from_url,
    main,
)
from licensestoic.models import ReviewAction

from factories import make_scan_result


class TestDetectProjectLicense:
    """Parametrised tests for auto-detection from various file formats."""

    def test_detects_mit_from_pyproject_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1.0"\nlicense = "MIT"\n'
        )
        assert _detect_project_license(tmp_path) == "MIT"

    def test_detects_apache_from_pyproject_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1.0"\nlicense = "Apache-2.0"\n'
        )
        assert _detect_project_license(tmp_path) == "Apache-2.0"

    def test_ignores_table_style_license_field(self, tmp_path: Path) -> None:
        """license = {text = "MIT"} starts with '{', should be skipped."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1.0"\n' 'license = {text = "MIT"}\n'
        )
        # The simple parser won't extract from table syntax,
        # but a LICENSE file fallback should work
        (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright 2026 Test\n")
        assert _detect_project_license(tmp_path) == "MIT"

    def test_detects_license_from_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"license": "ISC"}))
        assert _detect_project_license(tmp_path) == "ISC"

    def test_detects_mit_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright 2026\n")
        assert _detect_project_license(tmp_path) == "MIT"

    def test_detects_apache_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("Apache License\nVersion 2.0, January 2004\n")
        assert _detect_project_license(tmp_path) == "Apache-2.0"

    def test_detects_gpl3_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("GNU General Public License\nVersion 3, 29 June 2007\n")
        assert _detect_project_license(tmp_path) == "GPL-3.0-only"

    def test_detects_gpl2_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("GNU General Public License\nVersion 2, June 1991\n")
        assert _detect_project_license(tmp_path) == "GPL-2.0-only"

    def test_detects_bsd3_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("BSD 3-Clause License\n\n")
        assert _detect_project_license(tmp_path) == "BSD-3-Clause"

    def test_detects_bsd2_from_license_file(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("BSD 2-Clause License\n\n")
        assert _detect_project_license(tmp_path) == "BSD-2-Clause"

    def test_returns_none_when_nothing_found(self, tmp_path: Path) -> None:
        assert _detect_project_license(tmp_path) is None

    def test_invalid_spdx_in_pyproject_falls_through(self, tmp_path: Path) -> None:
        """Non-SPDX license string in pyproject should not be returned."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1.0"\n' 'license = "Some Custom License"\n'
        )
        assert _detect_project_license(tmp_path) is None


class TestLooksLikeRepoShorthand:
    def test_owner_repo(self) -> None:
        assert _looks_like_repo_shorthand("owner/repo") is True

    def test_local_path_not_shorthand(self, tmp_path: Path) -> None:
        # An existing directory should not be treated as shorthand
        subdir = tmp_path / "foo"
        subdir.mkdir()
        assert _looks_like_repo_shorthand(str(subdir)) is False

    def test_three_parts_not_shorthand(self) -> None:
        assert _looks_like_repo_shorthand("a/b/c") is False

    def test_empty_part_not_shorthand(self) -> None:
        assert _looks_like_repo_shorthand("/repo") is False

    def test_dot_prefix_not_shorthand(self) -> None:
        assert _looks_like_repo_shorthand("./repo") is False


class TestRepoNameFromUrl:
    def test_https_with_git_suffix(self) -> None:
        assert _repo_name_from_url("https://github.com/owner/repo.git") == "repo"

    def test_https_without_git_suffix(self) -> None:
        assert _repo_name_from_url("https://github.com/owner/repo") == "repo"

    def test_trailing_slash(self) -> None:
        assert _repo_name_from_url("https://github.com/owner/repo/") == "repo"

    def test_empty_url(self) -> None:
        assert _repo_name_from_url("") == "unknown"


class TestCliHelp:
    def test_help_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "LicenseStoic" in result.output
        assert "--license" in result.output

    def test_version_is_not_a_flag(self) -> None:
        """Ensure no accidental --version flag crashes."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        # Should fail gracefully (no such option)
        assert result.exit_code != 0


class TestCliExitCodes:
    @patch("licensestoic.cli.run_pipeline", new_callable=AsyncMock)
    def test_exit_0_when_no_conflicts(self, mock_pipeline: AsyncMock, tmp_path: Path) -> None:
        """Clean scan → exit 0."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "1.0"\nlicense = "MIT"\n' "dependencies = []\n"
        )
        mock_pipeline.return_value = (
            make_scan_result(review_action=ReviewAction.AUTO_APPLY),
            None,
        )

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path), "--license", "MIT"])
        assert result.exit_code == 0

    @patch("licensestoic.cli.run_pipeline", new_callable=AsyncMock)
    def test_exit_1_when_conflicts(self, mock_pipeline: AsyncMock, tmp_path: Path) -> None:
        """Conflicts found → exit 1."""
        from factories import make_conflict

        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "1.0"\nlicense = "MIT"\n' "dependencies = []\n"
        )
        mock_pipeline.return_value = (
            make_scan_result(conflicts=[make_conflict()]),
            None,
        )

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path), "--license", "MIT"])
        assert result.exit_code == 1

    def test_exit_1_for_nonexistent_path(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["/nonexistent/path/abc123", "--license", "MIT"])
        assert result.exit_code == 1
        assert "does not exist" in result.output

    def test_exit_1_when_no_license_detected(self, tmp_path: Path) -> None:
        """No license can be found and none provided → exit 1."""
        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])
        assert result.exit_code == 1
        assert "Could not detect" in result.output


class TestCliJsonReport:
    @patch("licensestoic.cli.run_pipeline", new_callable=AsyncMock)
    def test_json_report_saved(self, mock_pipeline: AsyncMock, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "1.0"\nlicense = "MIT"\n' "dependencies = []\n"
        )
        mock_pipeline.return_value = (
            make_scan_result(review_action=ReviewAction.AUTO_APPLY),
            None,
        )

        report_path = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(tmp_path), "--license", "MIT", "--json-report", str(report_path)],
        )
        assert result.exit_code == 0
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "project" in data
