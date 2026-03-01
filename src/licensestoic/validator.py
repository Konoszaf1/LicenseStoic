"""License compatibility validator — Layer 2.

Wraps flict (OSADL matrix) for deterministic compatibility verdicts.
Falls back to a built-in compatibility matrix when flict is not installed.

This module is the correctness authority. The LLM NEVER overrides its verdicts.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import ClassVar

from licensestoic.models import (
    CompatibilityResult,
    CompatibilityVerdict,
    Conflict,
    DependencyNode,
    DistributionType,
    IntegrationType,
)
from licensestoic.severity import compute_risk_severity

logger = logging.getLogger(__name__)

# Universally permissive / public-domain-equivalent licenses.
# These impose no meaningful restrictions and are compatible as a dependency
# with ANY project license. Checked first in _raw_check() for fast-path.
_PERMISSIVE_UNIVERSAL: frozenset[str] = frozenset(
    {
        "0BSD",
        "CC0-1.0",
        "Unlicense",
        "WTFPL",
        "ISC",
        "Zlib",
        "BSL-1.0",
    }
)

# Built-in compatibility matrix for common license pairs.
# This is a *subset* of the OSADL matrix covering the most common licenses.
# Used when flict is not installed (development, testing, CI).
# Format: (inbound_license, outbound_license) → compatible?
# "inbound" = the dependency, "outbound" = the project consuming it.
_BUILTIN_MATRIX: dict[tuple[str, str], bool] = {
    # Permissive → Permissive: always compatible
    ("MIT", "MIT"): True,
    ("MIT", "Apache-2.0"): True,
    ("MIT", "BSD-2-Clause"): True,
    ("MIT", "BSD-3-Clause"): True,
    ("Apache-2.0", "MIT"): True,
    ("Apache-2.0", "Apache-2.0"): True,
    ("Apache-2.0", "BSD-2-Clause"): True,
    ("Apache-2.0", "BSD-3-Clause"): True,
    ("BSD-2-Clause", "MIT"): True,
    ("BSD-2-Clause", "Apache-2.0"): True,
    ("BSD-3-Clause", "MIT"): True,
    ("BSD-3-Clause", "Apache-2.0"): True,
    # Permissive → Copyleft: always compatible (permissive can go into copyleft)
    ("MIT", "GPL-2.0-only"): True,
    ("MIT", "GPL-2.0-or-later"): True,
    ("MIT", "GPL-3.0-only"): True,
    ("MIT", "GPL-3.0-or-later"): True,
    ("MIT", "LGPL-2.1-only"): True,
    ("MIT", "LGPL-3.0-only"): True,
    ("MIT", "AGPL-3.0-only"): True,
    ("MIT", "MPL-2.0"): True,
    ("Apache-2.0", "GPL-3.0-only"): True,
    ("Apache-2.0", "GPL-3.0-or-later"): True,
    ("Apache-2.0", "LGPL-3.0-only"): True,
    ("Apache-2.0", "AGPL-3.0-only"): True,
    ("Apache-2.0", "MPL-2.0"): True,
    ("BSD-2-Clause", "GPL-2.0-only"): True,
    ("BSD-2-Clause", "GPL-3.0-only"): True,
    ("BSD-3-Clause", "GPL-2.0-only"): True,
    ("BSD-3-Clause", "GPL-3.0-only"): True,
    # Copyleft → Permissive: INCOMPATIBLE (strong copyleft cannot go into permissive)
    ("GPL-2.0-only", "MIT"): False,
    ("GPL-2.0-only", "Apache-2.0"): False,
    ("GPL-2.0-only", "BSD-2-Clause"): False,
    ("GPL-2.0-only", "BSD-3-Clause"): False,
    ("GPL-2.0-or-later", "MIT"): False,
    ("GPL-3.0-only", "MIT"): False,
    ("GPL-3.0-only", "Apache-2.0"): False,
    ("GPL-3.0-only", "BSD-2-Clause"): False,
    ("GPL-3.0-only", "BSD-3-Clause"): False,
    ("GPL-3.0-or-later", "MIT"): False,
    ("AGPL-3.0-only", "MIT"): False,
    ("AGPL-3.0-only", "Apache-2.0"): False,
    ("AGPL-3.0-only", "GPL-3.0-only"): False,
    ("AGPL-3.0-or-later", "MIT"): False,
    # Apache-2.0 → GPL-2.0: INCOMPATIBLE (patent clause conflict)
    ("Apache-2.0", "GPL-2.0-only"): False,
    ("Apache-2.0", "GPL-2.0-or-later"): False,
    # Copyleft → Same copyleft: compatible
    ("GPL-2.0-only", "GPL-2.0-only"): True,
    ("GPL-2.0-only", "GPL-2.0-or-later"): True,
    ("GPL-3.0-only", "GPL-3.0-only"): True,
    ("GPL-3.0-only", "GPL-3.0-or-later"): True,
    ("LGPL-2.1-only", "GPL-2.0-only"): True,
    ("LGPL-2.1-only", "GPL-2.0-or-later"): True,
    ("LGPL-2.1-only", "GPL-3.0-only"): True,
    ("LGPL-2.1-only", "LGPL-2.1-only"): True,
    ("LGPL-3.0-only", "GPL-3.0-only"): True,
    ("LGPL-3.0-only", "LGPL-3.0-only"): True,
    # GPL-2.0 → GPL-3.0: INCOMPATIBLE (only "or later" bridges this)
    ("GPL-2.0-only", "GPL-3.0-only"): False,
    ("GPL-3.0-only", "GPL-2.0-only"): False,
    # GPL-2.0-or-later → GPL-3.0: compatible (or-later allows upgrading)
    ("GPL-2.0-or-later", "GPL-3.0-only"): True,
    ("GPL-2.0-or-later", "GPL-3.0-or-later"): True,
    # MPL-2.0 specifics
    ("MPL-2.0", "MIT"): False,
    ("MPL-2.0", "Apache-2.0"): False,
    ("MPL-2.0", "GPL-2.0-only"): True,
    ("MPL-2.0", "GPL-3.0-only"): True,
    ("MPL-2.0", "MPL-2.0"): True,
    # LGPL → Permissive: context-dependent (depends on linking)
    ("LGPL-2.1-only", "MIT"): False,
    ("LGPL-2.1-only", "Apache-2.0"): False,
    ("LGPL-3.0-only", "MIT"): False,
    ("LGPL-3.0-only", "Apache-2.0"): False,
}

# Integration types that do not create distribution obligations.
_NON_DISTRIBUTING_INTEGRATIONS = frozenset(
    {
        IntegrationType.BUILD_TOOL,
        IntegrationType.TEST_ONLY,
        IntegrationType.DEV_ONLY,
    }
)


def _compute_unknown_severity(
    integration_type: IntegrationType,
    distribution_type: DistributionType,
) -> float:
    """Compute risk severity for a dependency with unknown license.

    Unknown = cannot verify compliance = inherently risky.
    Base severity is 0.6 (conservative mid-high), adjusted by context.
    """
    base = 0.6

    if distribution_type == DistributionType.SAAS:
        base = 0.7
    elif distribution_type == DistributionType.INTERNAL:
        base = 0.4

    if integration_type == IntegrationType.SUBPROCESS:
        base = max(base - 0.1, 0.2)

    return round(base, 2)


class LicenseCompatibilityValidator:
    """Deterministic license compatibility checker.

    Wraps flict for OSADL matrix lookups. Falls back to a built-in matrix
    when flict is unavailable. Never uses LLM reasoning for verdicts.
    """

    _flict_available: ClassVar[bool | None] = None

    def __init__(self, flict_path: str = "flict") -> None:
        self._flict_path = flict_path
        if LicenseCompatibilityValidator._flict_available is None:
            LicenseCompatibilityValidator._flict_available = self._check_flict()

    def check_pairwise(
        self,
        source_license: str,
        target_license: str,
        integration_type: IntegrationType,
        distribution_type: DistributionType,
    ) -> CompatibilityResult:
        """Check compatibility of two licenses.

        source_license = the dependency's license (inbound).
        target_license = the project's license (outbound).
        """
        verdict, rule_source = self._raw_check(source_license, target_license)

        # Apply integration context adjustments
        verdict = self._apply_integration_context(
            verdict, source_license, integration_type, distribution_type
        )

        severity = compute_risk_severity(
            source_license,
            target_license,
            integration_type,
            distribution_type,
            verdict,
        )

        explanation = self._build_explanation(
            source_license, target_license, verdict, integration_type, distribution_type
        )

        return CompatibilityResult(
            verdict=verdict,
            source_license=source_license,
            target_license=target_license,
            rule_source=rule_source,
            risk_severity=severity,
            explanation=explanation,
            requires_human_review=severity > 0.5 or verdict == CompatibilityVerdict.UNKNOWN,
        )

    def validate_dependency_graph(
        self,
        project_license: str,
        dependencies: list[DependencyNode],
        distribution_type: DistributionType,
    ) -> list[Conflict]:
        """Check all dependencies against the project license.

        Compound AND expressions: In package metadata, AND typically means the
        package is available under multiple licenses simultaneously (dual/multi-
        licensed). If ANY component of an AND expression is compatible with the
        project license, the package is treated as compatible — the user can
        satisfy obligations through the compatible component.

        OR expressions are handled at the identifier extraction level (the parser
        already splits them into individual identifiers for separate checking).
        """
        conflicts: list[Conflict] = []

        for dep in dependencies:
            if dep.integration_type in _NON_DISTRIBUTING_INTEGRATIONS:
                continue

            if dep.license_expression.identifiers:
                # Check all identifiers and collect results
                results: list[tuple[str, CompatibilityResult]] = []
                has_compatible = False
                for spdx_id in dep.license_expression.identifiers:
                    result = self.check_pairwise(
                        source_license=spdx_id,
                        target_license=project_license,
                        integration_type=dep.integration_type,
                        distribution_type=distribution_type,
                    )
                    results.append((spdx_id, result))
                    if result.verdict == CompatibilityVerdict.COMPATIBLE:
                        has_compatible = True

                # If any component is compatible (AND = multi-licensed), the
                # package as a whole is compatible — skip conflict generation.
                if has_compatible:
                    continue

                # All components are non-compatible — generate conflicts
                for spdx_id, result in results:
                    if result.verdict in (
                        CompatibilityVerdict.INCOMPATIBLE,
                        CompatibilityVerdict.UNKNOWN,
                        CompatibilityVerdict.CONTEXT_DEPENDENT,
                    ):
                        conflicts.append(
                            Conflict(
                                id=f"conflict-{dep.name}-{spdx_id}",
                                source_node=dep.name,
                                target_node="project",
                                source_license=spdx_id,
                                target_license=project_license,
                                distribution_type=distribution_type,
                                integration_type=dep.integration_type,
                                risk_severity=result.risk_severity,
                                rule_source=result.rule_source,
                                description=result.explanation,
                                transitive_chain=self._build_chain(dep, dependencies),
                            )
                        )
            else:
                # No license identifiers — cannot verify compatibility
                severity = _compute_unknown_severity(dep.integration_type, distribution_type)
                conflicts.append(
                    Conflict(
                        id=f"conflict-{dep.name}-UNKNOWN",
                        source_node=dep.name,
                        target_node="project",
                        source_license="UNKNOWN",
                        target_license=project_license,
                        distribution_type=distribution_type,
                        integration_type=dep.integration_type,
                        risk_severity=severity,
                        rule_source="unknown_license",
                        description=(
                            f"License for '{dep.name}' could not be determined. "
                            f"Cannot verify compatibility with {project_license}. "
                            f"Manual review required."
                        ),
                        transitive_chain=self._build_chain(dep, dependencies),
                    )
                )

        return conflicts

    # -- Private methods --

    def _raw_check(self, source: str, target: str) -> tuple[CompatibilityVerdict, str]:
        """Get raw compatibility verdict from flict or builtin matrix."""
        # Fast-path: universally permissive licenses are always compatible
        # as inbound (dependency) — they impose no restrictions on the project.
        if source in _PERMISSIVE_UNIVERSAL:
            return CompatibilityVerdict.COMPATIBLE, "permissive_universal"

        if self._flict_available:
            result = self._call_flict(source, target)
            if result is not None:
                return result, "osadl_matrix_via_flict"

        # Fall back to builtin matrix
        pair = (source, target)
        if pair in _BUILTIN_MATRIX:
            compat = _BUILTIN_MATRIX[pair]
            verdict = (
                CompatibilityVerdict.COMPATIBLE if compat else CompatibilityVerdict.INCOMPATIBLE
            )
            return verdict, "builtin_matrix"

        return CompatibilityVerdict.UNKNOWN, "not_in_matrix"

    def _apply_integration_context(
        self,
        verdict: CompatibilityVerdict,
        source_license: str,
        integration_type: IntegrationType,
        distribution_type: DistributionType,
    ) -> CompatibilityVerdict:
        """Adjust verdict based on how the dependency is integrated."""
        if verdict != CompatibilityVerdict.INCOMPATIBLE:
            return verdict

        # LGPL specifically allows dynamic linking without triggering copyleft
        if "LGPL" in source_license and integration_type == IntegrationType.DYNAMIC_LINK:
            return CompatibilityVerdict.CONTEXT_DEPENDENT

        # Subprocess isolation generally breaks copyleft propagation
        # (separate program, not derivative work) — but this is legally nuanced
        if integration_type == IntegrationType.SUBPROCESS:
            return CompatibilityVerdict.CONTEXT_DEPENDENT

        return verdict

    def _build_explanation(
        self,
        source: str,
        target: str,
        verdict: CompatibilityVerdict,
        integration: IntegrationType,
        distribution: DistributionType,
    ) -> str:
        """Generate a deterministic explanation string."""
        if verdict == CompatibilityVerdict.COMPATIBLE:
            return f"{source} is compatible with {target} for {distribution.value} distribution."

        if verdict == CompatibilityVerdict.UNKNOWN:
            return (
                f"Compatibility of {source} with {target} is not in the OSADL matrix. "
                f"Human review required."
            )

        if verdict == CompatibilityVerdict.CONTEXT_DEPENDENT:
            return (
                f"{source} may be compatible with {target} depending on integration details. "
                f"Current integration type is {integration.value}. Human review recommended."
            )

        # INCOMPATIBLE
        return (
            f"{source} is incompatible with {target} when distributed as {distribution.value}. "
            f"The {source} license obligations cannot be satisfied under {target} terms."
        )

    def _call_flict(self, source: str, target: str) -> CompatibilityVerdict | None:
        """Call flict CLI and parse result."""
        try:
            proc = subprocess.run(
                [self._flict_path, "verify", "-il", source, "-ol", target],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                logger.debug("flict returned non-zero for %s → %s: %s", source, target, proc.stderr)
                return None
            data = json.loads(proc.stdout)
            # flict output varies by version; handle common formats
            if isinstance(data, dict):
                status = data.get("status", data.get("compatibility", ""))
                if status in ("allowed", "Yes", "compatible"):
                    return CompatibilityVerdict.COMPATIBLE
                if status in ("denied", "No", "incompatible"):
                    return CompatibilityVerdict.INCOMPATIBLE
            return None
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    def _check_flict(self) -> bool:
        """Check if flict is installed and callable."""
        try:
            proc = subprocess.run(
                [self._flict_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            available = proc.returncode == 0
            if available:
                logger.info("flict found: %s", proc.stdout.strip())
            return available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("flict not found, using builtin compatibility matrix")
            return False

    @staticmethod
    def _build_chain(dep: DependencyNode, all_deps: list[DependencyNode]) -> list[str]:
        """Reconstruct transitive dependency chain."""
        chain = [dep.name]
        current = dep
        seen: set[str] = {dep.name}
        while current.parent and current.parent not in seen:
            chain.insert(0, current.parent)
            seen.add(current.parent)
            parent = next((d for d in all_deps if d.name == current.parent), None)
            if parent is None:
                break
            current = parent
        return chain
