"""Main pipeline orchestrator — ties all 5 layers together.

Scan → Validate → Enumerate Remediations → LLM Explain → Human Review Gate
"""

from __future__ import annotations

import logging
from pathlib import Path

from licensestoic.llm_explainer import (
    LLMExplanation,
    get_llm_explanation,
    validate_llm_output,
)
from licensestoic.models import (
    DependencyNode,
    DistributionType,
    ReliabilityWarning,
    ReviewAction,
    ScanResult,
)
from licensestoic.parsing import parse_license_expression
from licensestoic.remediation import RemediationEngine
from licensestoic.review_gate import determine_review_action
from licensestoic.scanner import scan_directory, scan_from_sbom
from licensestoic.validator import LicenseCompatibilityValidator

logger = logging.getLogger(__name__)


async def run_pipeline(
    project_path: str | Path,
    project_name: str,
    project_license: str,
    distribution_type: DistributionType = DistributionType.BINARY,
    use_scancode: bool = False,
    resolve_deps: bool = True,
    sbom_path: str | Path | None = None,
    anthropic_api_key: str | None = None,
) -> tuple[ScanResult, LLMExplanation | None]:
    """Run the full LicenseStoic pipeline.

    Returns (ScanResult, LLMExplanation or None).
    """
    project_path = Path(project_path)

    # Layer 1: Scanning
    logger.info("Layer 1: Scanning dependencies...")
    if sbom_path:
        dependencies = scan_from_sbom(sbom_path)
    else:
        dependencies = scan_directory(
            project_path, use_scancode=use_scancode, resolve_deps=resolve_deps
        )

    parsed_project_license = parse_license_expression(project_license)

    # Layer 2: Validation
    logger.info("Layer 2: Validating license compatibility...")
    validator = LicenseCompatibilityValidator()
    conflicts = validator.validate_dependency_graph(
        project_license, dependencies, distribution_type
    )

    # Compute reliability warnings
    reliability_warnings = _compute_reliability_warnings(dependencies)

    # Compute scan confidence
    if dependencies:
        confidences = [d.confidence for d in dependencies]
        scan_confidence = sum(confidences) / len(confidences)
    else:
        scan_confidence = 1.0

    # Layer 3: Remediation enumeration
    logger.info("Layer 3: Enumerating remediation options...")
    remediation_engine = RemediationEngine(validator)

    # Build partial result for remediation enumeration
    partial_result = ScanResult(
        project_name=project_name,
        project_license=parsed_project_license,
        distribution_type=distribution_type,
        dependencies=dependencies,
        conflicts=conflicts,
        remediations=[],
        scan_confidence=scan_confidence,
        reliability_warnings=reliability_warnings,
        review_action=ReviewAction.SUGGEST,  # placeholder
    )

    remediations = remediation_engine.enumerate_all(partial_result)

    # Build full result
    scan_result = ScanResult(
        project_name=project_name,
        project_license=parsed_project_license,
        distribution_type=distribution_type,
        dependencies=dependencies,
        conflicts=conflicts,
        remediations=remediations,
        scan_confidence=scan_confidence,
        reliability_warnings=reliability_warnings,
        review_action=ReviewAction.SUGGEST,  # will be updated below
    )

    # Layer 4: LLM explanation (optional)
    explanation: LLMExplanation | None = None
    if conflicts:
        logger.info("Layer 4: Generating explanations...")
        explanation = await get_llm_explanation(scan_result, api_key=anthropic_api_key)

        # AIQA: Validate LLM output against deterministic truth
        violations = validate_llm_output(explanation, scan_result)
        if violations:
            logger.warning("LLM output violations detected: %s", violations)
            scan_result.reliability_warnings.extend(
                [
                    ReliabilityWarning(
                        code="llm_violation",
                        message=v,
                    )
                    for v in violations
                ]
            )

    # Layer 5: Human review gate
    scan_result.review_action = determine_review_action(scan_result)

    logger.info(
        "Pipeline complete: %d deps, %d conflicts, review=%s",
        len(dependencies),
        len(conflicts),
        scan_result.review_action.value,
    )

    return scan_result, explanation


def _compute_reliability_warnings(
    dependencies: list[DependencyNode],
) -> list[ReliabilityWarning]:
    """Identify conditions where correctness may degrade."""
    warnings: list[ReliabilityWarning] = []

    # Deep transitive dependencies
    deep_deps = [d for d in dependencies if d.depth >= 4]
    if deep_deps:
        warnings.append(
            ReliabilityWarning(
                code="deep_transitive",
                message=(
                    f"{len(deep_deps)} dependencies at depth 4+ — "
                    f"transitive license info may be inferred, not scanned"
                ),
                affected_nodes=[d.name for d in deep_deps],
            )
        )

    # Low confidence dependencies
    low_conf = [d for d in dependencies if d.confidence < 0.5]
    if low_conf:
        warnings.append(
            ReliabilityWarning(
                code="low_confidence",
                message=(
                    f"{len(low_conf)} dependencies have low scan confidence (<0.5) — "
                    f"license info may be incomplete or incorrect"
                ),
                affected_nodes=[d.name for d in low_conf],
            )
        )

    # Unknown license dependencies (no identifiers at all)
    unknown_license = [
        d
        for d in dependencies
        if not d.license_expression.identifiers
        and d.license_expression.spdx_expression.upper() in ("UNKNOWN", "")
    ]
    if unknown_license:
        warnings.append(
            ReliabilityWarning(
                code="unknown_license",
                message=(
                    f"{len(unknown_license)} dependencies have unknown licenses — "
                    f"compatibility cannot be verified. Install project dependencies "
                    f"and re-scan, or provide an SBOM."
                ),
                affected_nodes=[d.name for d in unknown_license],
            )
        )

    # Non-SPDX license texts
    non_spdx = [d for d in dependencies if not d.license_expression.is_valid_spdx]
    if non_spdx:
        warnings.append(
            ReliabilityWarning(
                code="non_spdx",
                message=(
                    f"{len(non_spdx)} dependencies have non-standard license text — "
                    f"flagged for manual or LLM classification"
                ),
                affected_nodes=[d.name for d in non_spdx],
            )
        )

    return warnings
