"""End-to-end pipeline tests.

Verifies that all 5 layers work together correctly without external dependencies
(no flict CLI, no ScanCode, no LLM API).
"""

import pytest

from licensestoic.models import (
    DistributionType,
    IntegrationType,
    LicenseExpression,
    DependencyNode,
    ReviewAction,
)
from licensestoic.pipeline import run_pipeline, _compute_reliability_warnings


class TestReliabilityWarnings:
    """Test that reliability degradation is surfaced correctly."""

    def test_deep_deps_warning(self):
        deps = [
            DependencyNode(
                name=f"deep-{i}",
                license_expression=LicenseExpression(
                    spdx_expression="MIT",
                    identifiers=["MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=5,
                source="test",
            )
            for i in range(3)
        ]
        warnings = _compute_reliability_warnings(deps)
        codes = {w.code for w in warnings}
        assert "deep_transitive" in codes

    def test_low_confidence_warning(self):
        deps = [
            DependencyNode(
                name="unknown-dep",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
                confidence=0.3,
            )
        ]
        warnings = _compute_reliability_warnings(deps)
        codes = {w.code for w in warnings}
        assert "low_confidence" in codes

    def test_unknown_license_warning(self):
        deps = [
            DependencyNode(
                name="mystery-dep",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="pyproject.toml",
                confidence=0.3,
            )
        ]
        warnings = _compute_reliability_warnings(deps)
        codes = {w.code for w in warnings}
        assert "unknown_license" in codes

    def test_non_spdx_warning(self):
        deps = [
            DependencyNode(
                name="custom-dep",
                license_expression=LicenseExpression(
                    spdx_expression="Custom License",
                    identifiers=[],
                    is_valid_spdx=False,
                    raw_text="Custom License",
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            )
        ]
        warnings = _compute_reliability_warnings(deps)
        codes = {w.code for w in warnings}
        assert "non_spdx" in codes

    def test_no_warnings_for_clean_deps(self):
        deps = [
            DependencyNode(
                name="clean",
                license_expression=LicenseExpression(
                    spdx_expression="MIT",
                    identifiers=["MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
                confidence=1.0,
            )
        ]
        warnings = _compute_reliability_warnings(deps)
        assert len(warnings) == 0


class TestPipelineEndToEnd:
    """Full pipeline integration tests."""

    @pytest.mark.asyncio
    async def test_pipeline_runs_on_own_project(self, tmp_path):
        """Run the pipeline on a minimal test project."""
        # Create a minimal project
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test"\nversion = "1.0"\n' 'dependencies = []\nlicense = "MIT"\n'
        )
        license_file = tmp_path / "LICENSE"
        license_file.write_text("MIT License\n\nCopyright 2026 Test\n")

        scan_result, explanation = await run_pipeline(
            project_path=tmp_path,
            project_name="test-project",
            project_license="MIT",
            distribution_type=DistributionType.BINARY,
        )

        assert scan_result.project_name == "test-project"
        assert scan_result.project_license.spdx_expression == "MIT"
        assert scan_result.conflicts == []
        assert scan_result.review_action == ReviewAction.AUTO_APPLY

    @pytest.mark.asyncio
    async def test_unknown_deps_produce_conflicts(self, tmp_path):
        """A project with unresolvable deps should produce UNKNOWN conflicts."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test"\nversion = "1.0"\n'
            'dependencies = ["nonexistent-pkg-xyz"]\nlicense = "MIT"\n'
        )

        scan_result, explanation = await run_pipeline(
            project_path=tmp_path,
            project_name="test-project",
            project_license="MIT",
            distribution_type=DistributionType.BINARY,
        )

        # Should NOT be auto-apply (which implies "all clear")
        assert scan_result.review_action != ReviewAction.AUTO_APPLY
        # Should have at least one conflict for the unknown dep
        assert len(scan_result.conflicts) >= 1
        assert any(c.rule_source == "unknown_license" for c in scan_result.conflicts)
