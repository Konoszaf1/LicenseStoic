"""Risk severity scoring for license conflicts.

Anchored severity scale:
    0.0  — Attribution notice missing, permissive license. Trivially fixable.
    0.25 — Weak copyleft (LGPL) dynamically linked. Likely compliant.
    0.5  — File-level copyleft (MPL) mixed into proprietary codebase.
    0.75 — Strong copyleft (GPL) statically linked into permissive binary.
    1.0  — AGPL dependency in proprietary SaaS with no source disclosure.
"""

from __future__ import annotations

from licensestoic.models import (
    CompatibilityVerdict,
    DistributionType,
    IntegrationType,
)

# Copyleft strength baseline — derived from license obligations, not opinion.
_COPYLEFT_STRENGTH: dict[str, float] = {
    "AGPL-3.0-only": 1.0,
    "AGPL-3.0-or-later": 1.0,
    "GPL-3.0-only": 0.85,
    "GPL-3.0-or-later": 0.85,
    "GPL-2.0-only": 0.8,
    "GPL-2.0-or-later": 0.8,
    "MPL-2.0": 0.5,
    "EPL-2.0": 0.45,
    "LGPL-3.0-only": 0.4,
    "LGPL-3.0-or-later": 0.4,
    "LGPL-2.1-only": 0.35,
    "LGPL-2.1-or-later": 0.35,
    "EUPL-1.2": 0.5,
    "CECILL-2.1": 0.5,
    "OSL-3.0": 0.6,
}

# Default for unknown copyleft — conservative mid-range.
_DEFAULT_COPYLEFT_STRENGTH = 0.6


def compute_risk_severity(
    source_license: str,
    target_license: str,
    integration_type: IntegrationType,
    distribution_type: DistributionType,
    verdict: CompatibilityVerdict,
) -> float:
    """Compute risk severity (0.0–1.0) for a license conflict.

    Compatible pairs always return 0.0.
    For incompatible pairs, severity is derived from copyleft strength of the
    *source* license (the dependency), adjusted by integration and distribution
    context.
    """
    if verdict == CompatibilityVerdict.COMPATIBLE:
        return 0.0

    base = _COPYLEFT_STRENGTH.get(source_license, _DEFAULT_COPYLEFT_STRENGTH)

    # AGPL + SaaS is maximum exposure — network interaction clause triggers
    # even without binary distribution.
    if distribution_type == DistributionType.SAAS and "AGPL" in source_license:
        base = min(base + 0.15, 1.0)

    # Internal-only distribution reduces exposure significantly.
    if distribution_type == DistributionType.INTERNAL:
        base = max(base - 0.3, 0.1)

    # LGPL with dynamic linking is specifically designed to be compatible.
    if integration_type == IntegrationType.DYNAMIC_LINK and "LGPL" in source_license:
        base = max(base - 0.2, 0.1)

    # Static linking increases copyleft obligations.
    if integration_type == IntegrationType.STATIC_LINK:
        base = min(base + 0.1, 1.0)

    # Subprocess isolation weakens copyleft reach for most licenses.
    if integration_type == IntegrationType.SUBPROCESS:
        base = max(base - 0.15, 0.15)

    return round(base, 2)
