"""Human review gate — Layer 5.

Determines the appropriate review action for each conflict based on:
- Risk severity thresholds
- Whether LLM was involved in the recommendation
- Whether any licenses are unknown/ambiguous

Three tiers:
  AUTO_APPLY  — risk < 0.3 AND deterministic-only. Safe to apply without review.
  SUGGEST     — risk 0.3–0.7 OR LLM-involved. Present to user with explanation.
  ESCALATE    — risk > 0.7 OR unknown license. Requires expert/legal review.
"""

from __future__ import annotations

from typing import Any

from licensestoic.models import (
    Conflict,
    ReviewAction,
    ScanResult,
)


def determine_review_action(scan_result: ScanResult) -> ReviewAction:
    """Determine the overall review action for the entire scan."""
    if not scan_result.conflicts:
        return ReviewAction.AUTO_APPLY

    max_severity = max(c.risk_severity for c in scan_result.conflicts)
    has_unknown = any(
        c.rule_source in ("not_in_matrix", "unknown_license") for c in scan_result.conflicts
    )
    has_llm = any(r.llm_explanation is not None for r in scan_result.remediations)

    if has_unknown or max_severity > 0.7:
        return ReviewAction.ESCALATE
    if has_llm or max_severity > 0.3:
        return ReviewAction.SUGGEST
    return ReviewAction.AUTO_APPLY


def classify_conflict(conflict: Conflict) -> ReviewAction:
    """Classify a single conflict's required review level."""
    if conflict.rule_source in ("not_in_matrix", "unknown_license"):
        return ReviewAction.ESCALATE
    if conflict.risk_severity > 0.7:
        return ReviewAction.ESCALATE
    if conflict.risk_severity > 0.3:
        return ReviewAction.SUGGEST
    return ReviewAction.AUTO_APPLY


def generate_review_summary(scan_result: ScanResult) -> dict[str, Any]:
    """Generate a structured review summary for the operator."""
    escalate = []
    suggest = []
    auto = []

    for conflict in scan_result.conflicts:
        action = classify_conflict(conflict)
        entry = {
            "conflict_id": conflict.id,
            "source": conflict.source_node,
            "license": conflict.source_license,
            "severity": conflict.risk_severity,
            "description": conflict.description,
        }
        if action == ReviewAction.ESCALATE:
            escalate.append(entry)
        elif action == ReviewAction.SUGGEST:
            suggest.append(entry)
        else:
            auto.append(entry)

    return {
        "total_conflicts": len(scan_result.conflicts),
        "escalate": escalate,
        "suggest": suggest,
        "auto_apply": auto,
        "overall_action": determine_review_action(scan_result).value,
        "reliability_warnings": [
            {"code": w.code, "message": w.message} for w in scan_result.reliability_warnings
        ],
    }
