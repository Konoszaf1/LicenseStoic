"""Shared test factory functions.

Consolidates the duplicate _make_conflict(), _make_scan_result(), _FakeDist
helpers that were previously scattered across test files.

These are plain functions (not pytest fixtures), so they can be imported
directly from any test module.
"""

from __future__ import annotations

from email.message import Message

from licensestoic.models import (
    Conflict,
    DependencyNode,
    DistributionType,
    IntegrationType,
    LicenseExpression,
    RemediationOption,
    RemediationStrategy,
    ReviewAction,
    ScanResult,
)

# ---------------------------------------------------------------------------
# LicenseExpression factories
# ---------------------------------------------------------------------------


def make_license_expr(
    spdx: str = "MIT",
    identifiers: list[str] | None = None,
    *,
    valid: bool = True,
    raw_text: str | None = None,
) -> LicenseExpression:
    """Build a LicenseExpression with sensible defaults."""
    if identifiers is None:
        identifiers = [spdx] if valid else []
    if raw_text is None:
        raw_text = spdx
    return LicenseExpression(
        spdx_expression=spdx,
        identifiers=identifiers,
        is_valid_spdx=valid,
        raw_text=raw_text,
    )


# ---------------------------------------------------------------------------
# DependencyNode factory
# ---------------------------------------------------------------------------


def make_dep(
    name: str = "test-dep",
    license_spdx: str = "MIT",
    *,
    valid_spdx: bool = True,
    integration: IntegrationType = IntegrationType.STATIC_LINK,
    depth: int = 1,
    parent: str | None = None,
    source: str = "test",
    confidence: float = 1.0,
    version: str | None = None,
    identifiers: list[str] | None = None,
) -> DependencyNode:
    """Build a DependencyNode with sensible defaults."""
    return DependencyNode(
        name=name,
        version=version,
        license_expression=make_license_expr(
            license_spdx, identifiers=identifiers, valid=valid_spdx
        ),
        integration_type=integration,
        depth=depth,
        parent=parent,
        source=source,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Conflict factory
# ---------------------------------------------------------------------------


def make_conflict(
    source_license: str = "GPL-3.0-only",
    target_license: str = "MIT",
    *,
    severity: float = 0.8,
    rule_source: str = "builtin_matrix",
    source_node: str = "test-dep",
    integration: IntegrationType = IntegrationType.STATIC_LINK,
    distribution: DistributionType = DistributionType.BINARY,
    conflict_id: str | None = None,
    description: str = "Test conflict",
    transitive_chain: list[str] | None = None,
) -> Conflict:
    """Build a Conflict with sensible defaults."""
    return Conflict(
        id=conflict_id or f"conflict-{source_node}-{source_license}",
        source_node=source_node,
        target_node="project",
        source_license=source_license,
        target_license=target_license,
        distribution_type=distribution,
        integration_type=integration,
        risk_severity=severity,
        rule_source=rule_source,
        description=description,
        transitive_chain=transitive_chain or [],
    )


# ---------------------------------------------------------------------------
# ScanResult factory
# ---------------------------------------------------------------------------


def make_scan_result(
    project_license: str = "MIT",
    *,
    project_name: str = "test-project",
    deps: list[DependencyNode] | None = None,
    conflicts: list[Conflict] | None = None,
    remediations: list[RemediationOption] | None = None,
    distribution: DistributionType = DistributionType.BINARY,
    scan_confidence: float = 1.0,
    review_action: ReviewAction = ReviewAction.SUGGEST,
) -> ScanResult:
    """Build a ScanResult with sensible defaults."""
    return ScanResult(
        project_name=project_name,
        project_license=make_license_expr(project_license),
        distribution_type=distribution,
        dependencies=deps or [],
        conflicts=conflicts or [],
        remediations=remediations or [],
        scan_confidence=scan_confidence,
        review_action=review_action,
    )


# ---------------------------------------------------------------------------
# RemediationOption factory
# ---------------------------------------------------------------------------


def make_remediation(
    conflict_id: str = "conflict-test-dep-GPL-3.0-only",
    strategy: RemediationStrategy = RemediationStrategy.REPLACE_DEPENDENCY,
    *,
    description: str = "Replace dep with compatible alternative.",
    feasibility: float = 0.6,
) -> RemediationOption:
    """Build a RemediationOption with sensible defaults."""
    return RemediationOption(
        conflict_id=conflict_id,
        strategy=strategy,
        description=description,
        feasibility=feasibility,
    )


# ---------------------------------------------------------------------------
# importlib.metadata fakes for scanner tests
# ---------------------------------------------------------------------------


def make_dist_metadata(
    name: str,
    version: str = "1.0.0",
    license_field: str = "",
    classifiers: list[str] | None = None,
    license_expression: str | None = None,
) -> Message:
    """Build an email.message.Message mimicking importlib.metadata dist.metadata."""
    msg = Message()
    msg["Name"] = name
    msg["Version"] = version
    if license_field:
        msg["License"] = license_field
    if license_expression:
        msg["License-Expression"] = license_expression
    for c in classifiers or []:
        msg["Classifier"] = c
    return msg


class FakeDist:
    """Minimal fake for importlib.metadata distribution objects."""

    def __init__(self, metadata: Message) -> None:
        self.metadata = metadata


class FakeDistWithRequires:
    """Fake dist that also exposes requires() for transitive dep scanning."""

    def __init__(self, metadata: Message, requires: list[str] | None = None) -> None:
        self.metadata = metadata
        self._requires = requires

    @property
    def requires(self) -> list[str] | None:
        return self._requires
