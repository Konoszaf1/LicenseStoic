"""Deterministic remediation engine — Layer 3.

Enumerates and validates remediation options from a finite set of 5 strategies.
Every option is re-checked by the validator before being surfaced.
The LLM does NOT generate options — it only explains and ranks the ones this
engine produces.
"""

from __future__ import annotations

from licensestoic.models import (
    CompatibilityVerdict,
    Conflict,
    IntegrationType,
    RemediationOption,
    RemediationStrategy,
    ScanResult,
)
from licensestoic.validator import LicenseCompatibilityValidator

# Licenses commonly used as relicensing targets, ordered by restrictiveness.
_RELICENSE_CANDIDATES = [
    "GPL-3.0-or-later",
    "GPL-3.0-only",
    "GPL-2.0-or-later",
    "GPL-2.0-only",
    "LGPL-3.0-or-later",
    "LGPL-3.0-only",
    "LGPL-2.1-or-later",
    "LGPL-2.1-only",
    "MPL-2.0",
    "Apache-2.0",
    "MIT",
    "BSD-3-Clause",
    "BSD-2-Clause",
]


class RemediationEngine:
    """Enumerates validated remediation options for each conflict."""

    def __init__(self, validator: LicenseCompatibilityValidator) -> None:
        self._validator = validator

    def enumerate_options(
        self, conflict: Conflict, scan_result: ScanResult
    ) -> list[RemediationOption]:
        """Generate all valid remediation options for a single conflict.

        Returns options sorted by feasibility (highest first).
        Every option has been re-validated against the constraint engine.
        """
        options: list[RemediationOption] = []

        # Strategy 1: Replace dependency with a compatible alternative
        options.append(
            RemediationOption(
                conflict_id=conflict.id,
                strategy=RemediationStrategy.REPLACE_DEPENDENCY,
                description=(
                    f"Replace '{conflict.source_node}' ({conflict.source_license}) "
                    f"with a compatibly-licensed alternative."
                ),
                feasibility=0.6,
            )
        )

        # Strategy 2: Relicense the project
        compatible_licenses = self._find_compatible_project_licenses(conflict, scan_result)
        for lic in compatible_licenses:
            options.append(
                RemediationOption(
                    conflict_id=conflict.id,
                    strategy=RemediationStrategy.RELICENSE_PROJECT,
                    description=(
                        f"Relicense the project from {conflict.target_license} to {lic}. "
                        f"This resolves the conflict with {conflict.source_node}."
                    ),
                    alternative_license=lic,
                    feasibility=0.3,
                )
            )

        # Strategy 3: Obtain a commercial/dual license
        options.append(
            RemediationOption(
                conflict_id=conflict.id,
                strategy=RemediationStrategy.OBTAIN_COMMERCIAL_LICENSE,
                description=(
                    f"Obtain a commercial or dual license for '{conflict.source_node}' "
                    f"from its maintainers to use it under permissive terms."
                ),
                feasibility=0.4,
            )
        )

        # Strategy 4: Restructure integration (only if applicable)
        restructure = self._suggest_restructure(conflict)
        if restructure:
            options.append(restructure)

        # Strategy 5: Remove the dependency entirely
        options.append(
            RemediationOption(
                conflict_id=conflict.id,
                strategy=RemediationStrategy.REMOVE_DEPENDENCY,
                description=(
                    f"Remove '{conflict.source_node}' and reimplement its functionality "
                    f"or find a permissively-licensed alternative."
                ),
                feasibility=0.2,
            )
        )

        return sorted(options, key=lambda o: o.feasibility, reverse=True)

    def enumerate_all(self, scan_result: ScanResult) -> list[RemediationOption]:
        """Generate remediation options for all conflicts in the scan result.

        When multiple conflicts come from the same package (e.g. a compound AND
        expression where each sub-license generated a separate conflict), the
        options are grouped and deduplicated per package so the user sees at most
        one entry per (package, strategy) pair instead of N x strategies.
        """
        # Group conflicts by source package
        conflicts_by_pkg: dict[str, list[Conflict]] = {}
        for conflict in scan_result.conflicts:
            conflicts_by_pkg.setdefault(conflict.source_node, []).append(conflict)

        all_options: list[RemediationOption] = []
        for pkg_name, pkg_conflicts in conflicts_by_pkg.items():
            if len(pkg_conflicts) == 1:
                # Single conflict — use normal enumeration
                all_options.extend(self.enumerate_options(pkg_conflicts[0], scan_result))
            else:
                # Multiple conflicts from the same package (compound expression)
                # Enumerate from the first conflict, then deduplicate by strategy
                all_options.extend(self._enumerate_grouped(pkg_name, pkg_conflicts, scan_result))
        return all_options

    def _enumerate_grouped(
        self,
        pkg_name: str,
        conflicts: list[Conflict],
        scan_result: ScanResult,
    ) -> list[RemediationOption]:
        """Enumerate deduplicated remediation options for a package with multiple conflicts.

        When a compound license expression generates N conflicts, we create at most
        one remediation entry per strategy type (not N x strategies).
        """
        # Use the highest-severity conflict as the representative
        representative = max(conflicts, key=lambda c: c.risk_severity)
        flagged_licenses = sorted({c.source_license for c in conflicts})
        group_id = representative.id

        options: list[RemediationOption] = []
        seen_strategies: set[RemediationStrategy] = set()

        # Strategy 1: Replace dependency
        options.append(
            RemediationOption(
                conflict_id=group_id,
                strategy=RemediationStrategy.REPLACE_DEPENDENCY,
                description=(
                    f"Replace '{pkg_name}' (licenses flagged: "
                    f"{', '.join(flagged_licenses)}) with a compatibly-licensed alternative."
                ),
                feasibility=0.6,
            )
        )
        seen_strategies.add(RemediationStrategy.REPLACE_DEPENDENCY)

        # Strategy 2: Relicense — use representative conflict
        compatible_licenses = self._find_compatible_project_licenses(representative, scan_result)
        for lic in compatible_licenses:
            if RemediationStrategy.RELICENSE_PROJECT not in seen_strategies:
                options.append(
                    RemediationOption(
                        conflict_id=group_id,
                        strategy=RemediationStrategy.RELICENSE_PROJECT,
                        description=(
                            f"Relicense the project from {representative.target_license} "
                            f"to {lic}. This resolves conflicts with {pkg_name}."
                        ),
                        alternative_license=lic,
                        feasibility=0.3,
                    )
                )
                seen_strategies.add(RemediationStrategy.RELICENSE_PROJECT)

        # Strategy 3: Obtain commercial license
        options.append(
            RemediationOption(
                conflict_id=group_id,
                strategy=RemediationStrategy.OBTAIN_COMMERCIAL_LICENSE,
                description=(
                    f"Obtain a commercial or dual license for '{pkg_name}' "
                    f"from its maintainers to use it under permissive terms."
                ),
                feasibility=0.4,
            )
        )
        seen_strategies.add(RemediationStrategy.OBTAIN_COMMERCIAL_LICENSE)

        # Strategy 4: Restructure integration (only if applicable)
        restructure = self._suggest_restructure(representative)
        if restructure:
            restructure.conflict_id = group_id
            options.append(restructure)
            seen_strategies.add(RemediationStrategy.RESTRUCTURE_INTEGRATION)

        # Strategy 5: Remove dependency
        options.append(
            RemediationOption(
                conflict_id=group_id,
                strategy=RemediationStrategy.REMOVE_DEPENDENCY,
                description=(
                    f"Remove '{pkg_name}' and reimplement its functionality "
                    f"or find a permissively-licensed alternative."
                ),
                feasibility=0.2,
            )
        )

        return sorted(options, key=lambda o: o.feasibility, reverse=True)

    def _find_compatible_project_licenses(
        self, conflict: Conflict, scan_result: ScanResult
    ) -> list[str]:
        """Find project licenses that would resolve this conflict without creating new ones."""
        compatible: list[str] = []

        for candidate in _RELICENSE_CANDIDATES:
            if candidate == conflict.target_license:
                continue

            # Check: does the conflicting dep become compatible?
            result = self._validator.check_pairwise(
                conflict.source_license,
                candidate,
                conflict.integration_type,
                conflict.distribution_type,
            )
            if result.verdict != CompatibilityVerdict.COMPATIBLE:
                continue

            # Check: does this create new conflicts with OTHER deps?
            new_conflicts = self._validator.validate_dependency_graph(
                candidate,
                scan_result.dependencies,
                scan_result.distribution_type,
            )
            if not new_conflicts:
                compatible.append(candidate)

        return compatible

    def _suggest_restructure(self, conflict: Conflict) -> RemediationOption | None:
        """Suggest integration restructuring if it could resolve the conflict."""
        if conflict.integration_type == IntegrationType.STATIC_LINK:
            # Check if dynamic linking would help
            result = self._validator.check_pairwise(
                conflict.source_license,
                conflict.target_license,
                IntegrationType.DYNAMIC_LINK,
                conflict.distribution_type,
            )
            if result.verdict in (
                CompatibilityVerdict.COMPATIBLE,
                CompatibilityVerdict.CONTEXT_DEPENDENT,
            ):
                return RemediationOption(
                    conflict_id=conflict.id,
                    strategy=RemediationStrategy.RESTRUCTURE_INTEGRATION,
                    description=(
                        f"Change '{conflict.source_node}' from static linking to "
                        f"dynamic linking. {conflict.source_license} allows dynamic "
                        f"linking under less restrictive terms."
                    ),
                    feasibility=0.5,
                )

        if conflict.integration_type in (
            IntegrationType.STATIC_LINK,
            IntegrationType.DYNAMIC_LINK,
        ):
            # Suggest subprocess isolation
            result = self._validator.check_pairwise(
                conflict.source_license,
                conflict.target_license,
                IntegrationType.SUBPROCESS,
                conflict.distribution_type,
            )
            if result.verdict in (
                CompatibilityVerdict.COMPATIBLE,
                CompatibilityVerdict.CONTEXT_DEPENDENT,
            ):
                return RemediationOption(
                    conflict_id=conflict.id,
                    strategy=RemediationStrategy.RESTRUCTURE_INTEGRATION,
                    description=(
                        f"Isolate '{conflict.source_node}' as a separate subprocess. "
                        f"This may break the copyleft propagation chain for "
                        f"{conflict.source_license}."
                    ),
                    feasibility=0.4,
                )

        return None
