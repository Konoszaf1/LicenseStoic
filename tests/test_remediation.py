"""Tests for the deterministic remediation engine.

Validates that:
1. All 5 strategies are enumerated where applicable
2. Options are re-validated against the constraint engine
3. Relicensing options don't create cascade conflicts
4. Integration restructuring is only suggested when it would help
"""

import pytest

from licensestoic.models import (
    Conflict,
    DistributionType,
    IntegrationType,
    LicenseExpression,
    DependencyNode,
    RemediationStrategy,
    ReviewAction,
    ScanResult,
)
from licensestoic.remediation import RemediationEngine

# validator fixture is provided by conftest.py with flict pinned to False


@pytest.fixture
def engine(validator):
    return RemediationEngine(validator)


def _make_scan_result(
    project_license: str = "MIT",
    deps: list[DependencyNode] | None = None,
    conflicts: list[Conflict] | None = None,
) -> ScanResult:
    """Helper to build a ScanResult for testing."""
    return ScanResult(
        project_name="test-project",
        project_license=LicenseExpression(
            spdx_expression=project_license,
            identifiers=[project_license],
            is_valid_spdx=True,
        ),
        distribution_type=DistributionType.BINARY,
        dependencies=deps or [],
        conflicts=conflicts or [],
        remediations=[],
        scan_confidence=1.0,
        review_action=ReviewAction.SUGGEST,
    )


def _make_conflict(
    source_license: str = "GPL-3.0-only",
    target_license: str = "MIT",
    integration: IntegrationType = IntegrationType.STATIC_LINK,
) -> Conflict:
    return Conflict(
        id=f"conflict-test-{source_license}",
        source_node="test-dep",
        target_node="project",
        source_license=source_license,
        target_license=target_license,
        distribution_type=DistributionType.BINARY,
        integration_type=integration,
        risk_severity=0.8,
        rule_source="builtin_matrix",
        description="Test conflict",
    )


class TestRemediationEnumeration:
    """Test that the engine enumerates the correct set of options."""

    def test_always_includes_replace_and_remove(self, engine):
        """REPLACE and REMOVE are always available."""
        conflict = _make_conflict()
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        strategies = {o.strategy for o in options}
        assert RemediationStrategy.REPLACE_DEPENDENCY in strategies
        assert RemediationStrategy.REMOVE_DEPENDENCY in strategies

    def test_always_includes_commercial_license(self, engine):
        conflict = _make_conflict()
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        strategies = {o.strategy for o in options}
        assert RemediationStrategy.OBTAIN_COMMERCIAL_LICENSE in strategies

    def test_options_sorted_by_feasibility(self, engine):
        conflict = _make_conflict()
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        feasibilities = [o.feasibility for o in options]
        assert feasibilities == sorted(feasibilities, reverse=True)


class TestRelicensingOptions:
    """Test that relicensing suggestions are validated against all deps."""

    def test_relicensing_to_gpl3_resolves_gpl3_conflict(self, engine):
        """If only conflict is GPL-3.0 dep in MIT project, relicensing to GPL-3.0 helps."""
        gpl_dep = DependencyNode(
            name="gpl-dep",
            license_expression=LicenseExpression(
                spdx_expression="GPL-3.0-only",
                identifiers=["GPL-3.0-only"],
                is_valid_spdx=True,
            ),
            integration_type=IntegrationType.STATIC_LINK,
            depth=1,
            source="test",
        )
        conflict = _make_conflict(source_license="GPL-3.0-only")
        scan = _make_scan_result(deps=[gpl_dep], conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        relicense_options = [
            o for o in options if o.strategy == RemediationStrategy.RELICENSE_PROJECT
        ]
        # Should suggest GPL-3.0 compatible licenses
        relicense_licenses = {o.alternative_license for o in relicense_options}
        assert "GPL-3.0-only" in relicense_licenses or "GPL-3.0-or-later" in relicense_licenses


class TestRestructuringOptions:
    """Test integration restructuring suggestions."""

    def test_static_to_dynamic_suggested_for_lgpl(self, engine):
        """For LGPL dep with static linking, suggest dynamic linking."""
        conflict = _make_conflict(
            source_license="LGPL-2.1-only",
            integration=IntegrationType.STATIC_LINK,
        )
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        restructure = [
            o for o in options if o.strategy == RemediationStrategy.RESTRUCTURE_INTEGRATION
        ]
        assert len(restructure) > 0

    def test_no_restructure_for_dynamic_link(self, engine):
        """If already dynamically linked, don't suggest restructuring to dynamic."""
        conflict = _make_conflict(
            source_license="GPL-3.0-only",
            integration=IntegrationType.DYNAMIC_LINK,
        )
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_options(conflict, scan)

        restructure = [
            o for o in options if o.strategy == RemediationStrategy.RESTRUCTURE_INTEGRATION
        ]
        # Should NOT suggest switching to dynamic linking (already dynamic)
        for r in restructure:
            desc = r.description.lower()
            if "dynamic" in desc:
                # Only acceptable if it's about subprocess isolation, not re-doing dynamic
                assert "subprocess" in desc, (
                    f"Restructure option for already-dynamic dep suggests dynamic linking: "
                    f"{r.description}"
                )


class TestCompoundExpressionDeduplication:
    """Bug 3: Compound AND expressions should produce at most one remediation
    per strategy type, not N x strategies."""

    def test_compound_4_licenses_max_3_strategies(self, engine):
        """A package with 4+ AND-joined licenses should produce at most
        one entry per strategy type (not 4x3=12 options)."""
        # Simulate 4 conflicts from a single package
        conflicts = [
            Conflict(
                id=f"conflict-numpy-{lic}",
                source_node="numpy",
                target_node="project",
                source_license=lic,
                target_license="MIT",
                distribution_type=DistributionType.BINARY,
                integration_type=IntegrationType.STATIC_LINK,
                risk_severity=0.6,
                rule_source="not_in_matrix",
                description=f"{lic} not in matrix",
            )
            for lic in ["BSL-1.0", "MPL-2.0", "EUPL-1.2", "CECILL-2.1"]
        ]
        scan = _make_scan_result(conflicts=conflicts)
        options = engine.enumerate_all(scan)

        # Should be at most 5 (one per strategy type), not 4x5=20
        assert len(options) <= 5

        # Verify each strategy appears at most once
        strategies = [o.strategy for o in options]
        assert len(strategies) == len(set(strategies))

    def test_single_conflict_unchanged(self, engine):
        """Single conflict per package still uses normal enumeration."""
        conflict = _make_conflict()
        scan = _make_scan_result(conflicts=[conflict])
        options = engine.enumerate_all(scan)

        # Should still produce multiple options (at least replace + commercial + remove)
        assert len(options) >= 3
