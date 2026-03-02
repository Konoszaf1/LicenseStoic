"""Ground-truth tests for the license compatibility validator.

These tests validate against known-correct compatibility verdicts from the
OSADL matrix. This is the core AIQA correctness layer — if these tests pass,
the deterministic engine is producing legally accurate results.

The test cases are sourced from:
- OSADL compatibility matrix (https://www.osadl.org/Access-to-raw-data.oj-19-1.html)
- FSF license compatibility guides
- SPDX legal team compatibility recommendations
"""

import pytest

from licensestoic.models import (
    CompatibilityVerdict,
    DependencyNode,
    DistributionType,
    IntegrationType,
    LicenseExpression,
)

# validator fixture is provided by conftest.py with flict pinned to False

# ---------------------------------------------------------------------------
# Ground-truth pairwise compatibility tests (OSADL matrix)
# ---------------------------------------------------------------------------


class TestPermissiveToPermissive:
    """Permissive licenses are always compatible with each other."""

    @pytest.mark.parametrize(
        "source,target",
        [
            ("MIT", "MIT"),
            ("MIT", "Apache-2.0"),
            ("MIT", "BSD-2-Clause"),
            ("MIT", "BSD-3-Clause"),
            ("Apache-2.0", "MIT"),
            ("Apache-2.0", "Apache-2.0"),
            ("BSD-2-Clause", "MIT"),
            ("BSD-3-Clause", "Apache-2.0"),
        ],
    )
    def test_permissive_compatible(self, validator, source, target):
        result = validator.check_pairwise(
            source, target, IntegrationType.STATIC_LINK, DistributionType.BINARY
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE
        assert result.risk_severity == 0.0


class TestPermissiveToCopyleft:
    """Permissive code CAN be included in copyleft projects."""

    @pytest.mark.parametrize(
        "source,target",
        [
            ("MIT", "GPL-2.0-only"),
            ("MIT", "GPL-3.0-only"),
            ("MIT", "LGPL-2.1-only"),
            ("MIT", "AGPL-3.0-only"),
            ("Apache-2.0", "GPL-3.0-only"),
            ("BSD-2-Clause", "GPL-2.0-only"),
            ("BSD-3-Clause", "GPL-3.0-only"),
        ],
    )
    def test_permissive_into_copyleft_compatible(self, validator, source, target):
        result = validator.check_pairwise(
            source, target, IntegrationType.STATIC_LINK, DistributionType.BINARY
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE


class TestCopyleftToPermissive:
    """Copyleft code CANNOT be included in permissive projects (binary dist)."""

    @pytest.mark.parametrize(
        "source,target",
        [
            ("GPL-2.0-only", "MIT"),
            ("GPL-3.0-only", "MIT"),
            ("GPL-3.0-only", "Apache-2.0"),
            ("GPL-2.0-or-later", "MIT"),
            ("GPL-3.0-or-later", "MIT"),
            ("AGPL-3.0-only", "MIT"),
            ("AGPL-3.0-only", "Apache-2.0"),
        ],
    )
    def test_copyleft_into_permissive_incompatible(self, validator, source, target):
        result = validator.check_pairwise(
            source, target, IntegrationType.STATIC_LINK, DistributionType.BINARY
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_severity > 0.0


class TestApacheGPL2Conflict:
    """Apache-2.0 has a patent clause that conflicts with GPL-2.0."""

    def test_apache_into_gpl2_incompatible(self, validator):
        """Apache-2.0 code cannot go into GPL-2.0-only projects."""
        result = validator.check_pairwise(
            "Apache-2.0",
            "GPL-2.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_apache_into_gpl3_compatible(self, validator):
        """Apache-2.0 code CAN go into GPL-3.0 projects (resolved in GPL-3.0)."""
        result = validator.check_pairwise(
            "Apache-2.0",
            "GPL-3.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE


class TestGPLVersioning:
    """GPL version compatibility — critical legal distinctions."""

    def test_gpl2_only_not_compatible_with_gpl3(self, validator):
        """GPL-2.0-only code CANNOT be used in GPL-3.0-only projects."""
        result = validator.check_pairwise(
            "GPL-2.0-only",
            "GPL-3.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_gpl2_or_later_compatible_with_gpl3(self, validator):
        """GPL-2.0-or-later CAN be upgraded to GPL-3.0."""
        result = validator.check_pairwise(
            "GPL-2.0-or-later",
            "GPL-3.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_gpl3_not_compatible_with_gpl2(self, validator):
        """GPL-3.0-only code CANNOT be downgraded to GPL-2.0-only."""
        result = validator.check_pairwise(
            "GPL-3.0-only",
            "GPL-2.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE


class TestLGPLDynamicLinking:
    """LGPL specifically allows dynamic linking without copyleft propagation."""

    def test_lgpl_static_link_incompatible(self, validator):
        result = validator.check_pairwise(
            "LGPL-2.1-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        # Static linking with LGPL into MIT is incompatible
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_lgpl_dynamic_link_context_dependent(self, validator):
        """LGPL + dynamic linking becomes context-dependent, not a hard conflict."""
        result = validator.check_pairwise(
            "LGPL-2.1-only",
            "MIT",
            IntegrationType.DYNAMIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.CONTEXT_DEPENDENT
        # Risk should be lower than static linking
        assert result.risk_severity < 0.5


class TestMPLCompatibility:
    """MPL-2.0 is file-level copyleft — compatible with GPL but not permissive."""

    def test_mpl_into_permissive_incompatible(self, validator):
        result = validator.check_pairwise(
            "MPL-2.0",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_mpl_into_gpl3_compatible(self, validator):
        result = validator.check_pairwise(
            "MPL-2.0",
            "GPL-3.0-only",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE


class TestAGPLSaaS:
    """AGPL-3.0 has network interaction clause — maximum SaaS risk."""

    def test_agpl_saas_maximum_severity(self, validator):
        result = validator.check_pairwise(
            "AGPL-3.0-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.SAAS,
        )
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_severity >= 0.9  # near-maximum


# ---------------------------------------------------------------------------
# Integration context tests
# ---------------------------------------------------------------------------


class TestIntegrationTypeExclusions:
    """Build tools, test deps, and dev deps don't create distribution obligations."""

    @pytest.mark.parametrize(
        "integration",
        [IntegrationType.BUILD_TOOL, IntegrationType.TEST_ONLY, IntegrationType.DEV_ONLY],
    )
    def test_non_distributing_deps_skipped(self, validator, integration):
        """GPL-3.0 build/test/dev tool should NOT create a conflict."""
        deps = [
            DependencyNode(
                name="gpl-tool",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only",
                    identifiers=["GPL-3.0-only"],
                    is_valid_spdx=True,
                ),
                integration_type=integration,
                depth=1,
                source="test",
            )
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0


# ---------------------------------------------------------------------------
# Dependency graph validation tests
# ---------------------------------------------------------------------------


class TestDependencyGraphValidation:
    """End-to-end validation of dependency graphs."""

    def test_clean_project_no_conflicts(self, validator):
        deps = [
            DependencyNode(
                name="requests",
                license_expression=LicenseExpression(
                    spdx_expression="Apache-2.0",
                    identifiers=["Apache-2.0"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
            DependencyNode(
                name="click",
                license_expression=LicenseExpression(
                    spdx_expression="BSD-3-Clause",
                    identifiers=["BSD-3-Clause"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0

    def test_gpl_in_mit_project_creates_conflict(self, validator):
        deps = [
            DependencyNode(
                name="gpl-lib",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only",
                    identifiers=["GPL-3.0-only"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 1
        assert conflicts[0].source_license == "GPL-3.0-only"
        assert conflicts[0].risk_severity > 0.5

    def test_transitive_conflict_detected(self, validator):
        """A transitive GPL dep should still be detected."""
        deps = [
            DependencyNode(
                name="wrapper",
                license_expression=LicenseExpression(
                    spdx_expression="MIT",
                    identifiers=["MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
            DependencyNode(
                name="deep-gpl",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only",
                    identifiers=["GPL-3.0-only"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=2,
                parent="wrapper",
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 1
        assert conflicts[0].source_node == "deep-gpl"
        assert "wrapper" in conflicts[0].transitive_chain


# ---------------------------------------------------------------------------
# Severity scoring tests
# ---------------------------------------------------------------------------


class TestUnknownLicenseHandling:
    """Deps with empty identifiers should generate UNKNOWN conflicts."""

    def test_unknown_dep_generates_conflict(self, validator):
        """A dependency with no identifiers should produce a conflict."""
        deps = [
            DependencyNode(
                name="mystery-lib",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="pyproject.toml",
                confidence=0.3,
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 1
        assert conflicts[0].source_license == "UNKNOWN"
        assert conflicts[0].rule_source == "unknown_license"
        assert conflicts[0].risk_severity > 0

    def test_unknown_dev_dep_skipped(self, validator):
        """A dev-only dep with unknown license should NOT generate a conflict."""
        deps = [
            DependencyNode(
                name="dev-tool",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.DEV_ONLY,
                depth=1,
                source="pyproject.toml",
                confidence=0.3,
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0

    def test_unknown_saas_higher_severity(self, validator):
        """Unknown dep in SaaS context should have higher severity."""
        deps = [
            DependencyNode(
                name="mystery-lib",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="pyproject.toml",
                confidence=0.3,
            ),
        ]
        binary_conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        saas_conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.SAAS)
        assert saas_conflicts[0].risk_severity > binary_conflicts[0].risk_severity

    def test_mixed_known_and_unknown_deps(self, validator):
        """Known GPL conflict AND unknown dep both produce conflicts."""
        deps = [
            DependencyNode(
                name="gpl-lib",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only",
                    identifiers=["GPL-3.0-only"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
            DependencyNode(
                name="mystery-lib",
                license_expression=LicenseExpression(
                    spdx_expression="UNKNOWN",
                    identifiers=[],
                    is_valid_spdx=False,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="pyproject.toml",
                confidence=0.3,
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 2
        rule_sources = {c.rule_source for c in conflicts}
        assert "builtin_matrix" in rule_sources
        assert "unknown_license" in rule_sources


class TestSeverityAnchors:
    """Verify the 5 anchored severity examples produce expected ranges."""

    def test_permissive_compatible_severity_zero(self, validator):
        """Compatible pair → severity 0.0."""
        result = validator.check_pairwise(
            "MIT",
            "Apache-2.0",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.risk_severity == 0.0

    def test_lgpl_dynamic_low_severity(self, validator):
        """LGPL + dynamic link → low severity (~0.15)."""
        result = validator.check_pairwise(
            "LGPL-2.1-only",
            "MIT",
            IntegrationType.DYNAMIC_LINK,
            DistributionType.BINARY,
        )
        assert 0.0 < result.risk_severity <= 0.3

    def test_gpl3_static_high_severity(self, validator):
        """GPL-3.0 static link into MIT → high severity (~0.75+)."""
        result = validator.check_pairwise(
            "GPL-3.0-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        assert result.risk_severity >= 0.7

    def test_agpl_saas_maximum_severity(self, validator):
        """AGPL + SaaS → near-maximum severity (~0.95+)."""
        result = validator.check_pairwise(
            "AGPL-3.0-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.SAAS,
        )
        assert result.risk_severity >= 0.9

    def test_internal_distribution_reduces_severity(self, validator):
        """Internal-only distribution significantly reduces severity."""
        binary_result = validator.check_pairwise(
            "GPL-3.0-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.BINARY,
        )
        internal_result = validator.check_pairwise(
            "GPL-3.0-only",
            "MIT",
            IntegrationType.STATIC_LINK,
            DistributionType.INTERNAL,
        )
        assert internal_result.risk_severity < binary_result.risk_severity


# ---------------------------------------------------------------------------
# Bug 1: Universally permissive licenses
# ---------------------------------------------------------------------------


class TestPermissiveUniversal:
    """Universally permissive / public-domain-equivalent licenses are compatible
    with every project license."""

    @pytest.mark.parametrize(
        "source",
        ["0BSD", "Zlib", "CC0-1.0", "Unlicense", "WTFPL", "ISC"],
    )
    @pytest.mark.parametrize(
        "target",
        ["MIT", "Apache-2.0", "GPL-3.0-only", "AGPL-3.0-only", "MPL-2.0"],
    )
    def test_universal_permissive_compatible(self, validator, source, target):
        result = validator.check_pairwise(
            source, target, IntegrationType.STATIC_LINK, DistributionType.BINARY
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE
        assert result.risk_severity == 0.0
        assert result.rule_source == "permissive_universal"

    @pytest.mark.parametrize("source", ["0BSD", "CC0-1.0", "ISC"])
    def test_universal_permissive_saas(self, validator, source):
        """Universally permissive licenses are fine even in SaaS."""
        result = validator.check_pairwise(
            source, "MIT", IntegrationType.STATIC_LINK, DistributionType.SAAS
        )
        assert result.verdict == CompatibilityVerdict.COMPATIBLE
        assert result.risk_severity == 0.0


# ---------------------------------------------------------------------------
# Bug 5: Compound AND expression handling
# ---------------------------------------------------------------------------


class TestCompoundAndExpressions:
    """AND expressions in package metadata (dual-licensed) should pass if
    any component is compatible."""

    def test_mpl_and_mit_against_mit_compatible(self, validator):
        """MPL-2.0 AND MIT against MIT -> compatible (MIT component matches)."""
        deps = [
            DependencyNode(
                name="tqdm",
                license_expression=LicenseExpression(
                    spdx_expression="MPL-2.0 AND MIT",
                    identifiers=["MPL-2.0", "MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0

    def test_gpl3_and_mit_against_mit_compatible(self, validator):
        """GPL-3.0-only AND MIT against MIT -> compatible (MIT component matches)."""
        deps = [
            DependencyNode(
                name="dual-lib",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only AND MIT",
                    identifiers=["GPL-3.0-only", "MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0

    def test_gpl3_and_agpl3_against_mit_incompatible(self, validator):
        """GPL-3.0-only AND AGPL-3.0-only against MIT -> incompatible (neither
        is permissive enough)."""
        deps = [
            DependencyNode(
                name="copyleft-lib",
                license_expression=LicenseExpression(
                    spdx_expression="GPL-3.0-only AND AGPL-3.0-only",
                    identifiers=["GPL-3.0-only", "AGPL-3.0-only"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) >= 1

    def test_compound_with_universal_permissive(self, validator):
        """0BSD AND Zlib AND CC0-1.0 AND MIT against MIT -> compatible."""
        deps = [
            DependencyNode(
                name="numpy",
                license_expression=LicenseExpression(
                    spdx_expression="0BSD AND Zlib AND CC0-1.0 AND MIT",
                    identifiers=["0BSD", "Zlib", "CC0-1.0", "MIT"],
                    is_valid_spdx=True,
                ),
                integration_type=IntegrationType.STATIC_LINK,
                depth=1,
                source="test",
            ),
        ]
        conflicts = validator.validate_dependency_graph("MIT", deps, DistributionType.BINARY)
        assert len(conflicts) == 0
