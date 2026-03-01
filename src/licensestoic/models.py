"""Pydantic v2 data models for LicenseStoic.

All core domain types used across the pipeline:
Scan → Validate → Enumerate Remediations → LLM Explain → Human Review Gate.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class DistributionType(str, Enum):
    """How the project is distributed to end users."""

    BINARY = "binary"
    SOURCE = "source"
    SAAS = "saas"
    INTERNAL = "internal"
    LIBRARY = "library"


class IntegrationType(str, Enum):
    """How a dependency is integrated into the consuming project."""

    STATIC_LINK = "static_link"
    DYNAMIC_LINK = "dynamic_link"
    SUBPROCESS = "subprocess"
    BUILD_TOOL = "build_tool"
    TEST_ONLY = "test_only"
    DEV_ONLY = "dev_only"


class RemediationStrategy(str, Enum):
    """The five known remediation strategies (finite option space)."""

    REPLACE_DEPENDENCY = "replace_dependency"
    RELICENSE_PROJECT = "relicense_project"
    OBTAIN_COMMERCIAL_LICENSE = "obtain_commercial_license"
    RESTRUCTURE_INTEGRATION = "restructure_integration"
    REMOVE_DEPENDENCY = "remove_dependency"


class ReviewAction(str, Enum):
    """Human review gate decision."""

    AUTO_APPLY = "auto_apply"
    SUGGEST = "suggest"
    ESCALATE = "escalate"


class CompatibilityVerdict(str, Enum):
    """Result of a pairwise license compatibility check."""

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"
    CONTEXT_DEPENDENT = "context_dependent"


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------


class LicenseExpression(BaseModel):
    """Parsed SPDX license expression."""

    spdx_expression: str
    identifiers: list[str]
    is_valid_spdx: bool
    is_deprecated: bool = False
    raw_text: str | None = None


class DependencyNode(BaseModel):
    """A node in the dependency graph."""

    name: str
    version: str | None = None
    license_expression: LicenseExpression
    integration_type: IntegrationType
    depth: int = Field(ge=0)
    parent: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class CompatibilityResult(BaseModel):
    """Structured output from a pairwise compatibility check."""

    verdict: CompatibilityVerdict
    source_license: str
    target_license: str
    rule_source: str
    risk_severity: float = Field(ge=0.0, le=1.0)
    explanation: str
    requires_human_review: bool


class Conflict(BaseModel):
    """A detected license incompatibility."""

    id: str
    source_node: str
    target_node: str
    source_license: str
    target_license: str
    distribution_type: DistributionType
    integration_type: IntegrationType
    risk_severity: float = Field(ge=0.0, le=1.0)
    rule_source: str
    description: str
    transitive_chain: list[str] = Field(default_factory=list)


class RemediationOption(BaseModel):
    """A validated remediation for a conflict."""

    conflict_id: str
    strategy: RemediationStrategy
    description: str
    validated: bool = True
    feasibility: float = Field(ge=0.0, le=1.0)
    alternative_package: str | None = None
    alternative_license: str | None = None
    llm_explanation: str | None = None
    engineering_cost_rank: int | None = None


class ReliabilityWarning(BaseModel):
    """A signal that correctness may be degraded."""

    code: str
    message: str
    affected_nodes: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete output of a LicenseStoic analysis."""

    project_name: str
    project_license: LicenseExpression
    distribution_type: DistributionType
    dependencies: list[DependencyNode]
    conflicts: list[Conflict]
    remediations: list[RemediationOption]
    scan_confidence: float = Field(ge=0.0, le=1.0)
    reliability_warnings: list[ReliabilityWarning] = Field(default_factory=list)
    review_action: ReviewAction
