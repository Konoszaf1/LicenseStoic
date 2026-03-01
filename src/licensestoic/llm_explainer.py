"""LLM explanation layer — Layer 4.

Bounded LLM role: explains conflicts in plain language and ranks pre-validated
remediation options by engineering cost. The LLM NEVER:
- Makes compatibility verdicts (that's the validator's job)
- Invents remediation options (that's the remediation engine's job)
- Provides legal advice (it provides engineering guidance with caveats)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from licensestoic.models import ScanResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the explanation layer of LicenseStoic, an open source license compliance tool.
Your role is strictly bounded:

## What You Do
- Explain license conflicts in plain language for developers
- Rank pre-validated remediation options by estimated engineering cost
- Classify ambiguous license texts that scanners flagged as "unknown"
- Summarize the overall compliance state of a project

## What You Do NOT Do
- You NEVER determine whether two licenses are compatible. That is decided by \
the OSADL matrix via flict. If you disagree with a compatibility verdict, say so \
but DO NOT override it.
- You NEVER invent remediation options. You only explain and rank options that \
have been pre-validated by the deterministic engine.
- You NEVER state that a license conflict "isn't really a problem" or can be \
"safely ignored." All conflicts are surfaced to the user.
- You NEVER provide legal advice. You provide engineering guidance for resolving \
technical compliance issues. Always include the caveat that legal counsel should \
review significant licensing decisions.

## Output Format
Respond ONLY with valid JSON matching this schema:
{
  "conflict_explanations": [
    {
      "conflict_id": "string",
      "plain_language": "string (2-4 sentences, no legal jargon)",
      "severity_context": "string (why this severity level)"
    }
  ],
  "remediation_rankings": [
    {
      "conflict_id": "string",
      "ranked_options": [
        {
          "strategy": "string",
          "rank": "integer (1 = recommended)",
          "engineering_cost_explanation": "string",
          "estimated_effort": "trivial | moderate | significant | major"
        }
      ]
    }
  ],
  "ambiguous_licenses": [
    {
      "raw_text": "string",
      "likely_spdx": "string | null",
      "confidence": "float 0.0-1.0",
      "reasoning": "string"
    }
  ],
  "overall_summary": "string (3-5 sentences)"
}

## Handling Ambiguity
When classifying ambiguous license text:
- If confidence < 0.7, set likely_spdx to null and explain why
- NEVER guess between GPL-2.0-only and GPL-2.0-or-later — this distinction has \
major legal implications. Flag as ambiguous.
- NEVER assume "BSD" without a version. It could be BSD-2-Clause, BSD-3-Clause, \
or BSD-4-Clause (which has the advertising clause).
- State your reasoning transparently so a human can evaluate it.
"""


@dataclass
class LLMExplanation:
    """Parsed LLM response."""

    conflict_explanations: list[dict[str, Any]]
    remediation_rankings: list[dict[str, Any]]
    ambiguous_licenses: list[dict[str, Any]]
    overall_summary: str
    raw_response: str


def build_llm_prompt(scan_result: ScanResult) -> str:
    """Build the user prompt with conflict data for the LLM."""
    conflicts_data = [c.model_dump() for c in scan_result.conflicts]
    remediations_data = [r.model_dump() for r in scan_result.remediations]
    deps_summary = [
        {"name": d.name, "license": d.license_expression.spdx_expression, "depth": d.depth}
        for d in scan_result.dependencies
    ]

    ambiguous = [
        d
        for d in scan_result.dependencies
        if not d.license_expression.is_valid_spdx and d.license_expression.raw_text
    ]
    ambiguous_data = [
        {"name": d.name, "raw_text": d.license_expression.raw_text} for d in ambiguous
    ]

    prompt = (
        f"Project: {scan_result.project_name}\n"
        f"Project license: {scan_result.project_license.spdx_expression}\n"
        f"Distribution type: {scan_result.distribution_type.value}\n"
        f"Total dependencies: {len(scan_result.dependencies)}\n\n"
        f"## Conflicts (validated by OSADL matrix — do not override):\n"
        f"{json.dumps(conflicts_data, indent=2)}\n\n"
        f"## Pre-validated remediation options (do not invent new ones):\n"
        f"{json.dumps(remediations_data, indent=2)}\n\n"
        f"## Dependency summary:\n"
        f"{json.dumps(deps_summary, indent=2)}\n\n"
    )

    if ambiguous_data:
        prompt += (
            f"## Ambiguous license texts (classify these):\n"
            f"{json.dumps(ambiguous_data, indent=2)}\n\n"
        )

    prompt += (
        "Explain each conflict in plain language, rank the remediation options "
        "by engineering cost, classify any ambiguous licenses, and provide an "
        "overall summary. Respond ONLY with the JSON format specified in your instructions."
    )

    return prompt


async def get_llm_explanation(
    scan_result: ScanResult,
    api_key: str | None = None,
) -> LLMExplanation:
    """Get LLM explanation for conflicts and remediation ranking.

    Uses the Anthropic Claude API. Falls back to a stub if no API key.
    """
    if not scan_result.conflicts:
        return LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary="No license conflicts detected. The project's dependencies "
            "are compatible with its declared license.",
            raw_response="{}",
        )

    if not api_key:
        return _generate_stub_explanation(scan_result)

    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=api_key)
        user_prompt = build_llm_prompt(scan_result)

        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        block = message.content[0]
        raw = block.text if hasattr(block, "text") else str(block)
        return _parse_llm_response(raw)

    except Exception:
        logger.warning("LLM API call failed, using stub explanation", exc_info=True)
        return _generate_stub_explanation(scan_result)


def validate_llm_output(
    explanation: LLMExplanation,
    scan_result: ScanResult,
) -> list[str]:
    """Adversarial validation: check that LLM output doesn't violate boundaries.

    Returns a list of violations (empty = clean).
    This is the AIQA layer — the LLM is checked against the deterministic truth.
    """
    violations: list[str] = []

    valid_conflict_ids = {c.id for c in scan_result.conflicts}
    valid_strategies = {r.strategy.value for r in scan_result.remediations}

    # Check 1: LLM must not reference conflicts that don't exist
    for expl in explanation.conflict_explanations:
        if expl.get("conflict_id") not in valid_conflict_ids:
            violations.append(f"LLM referenced non-existent conflict: {expl.get('conflict_id')}")

    # Check 2: LLM must not invent remediation strategies
    for ranking in explanation.remediation_rankings:
        for opt in ranking.get("ranked_options", []):
            if opt.get("strategy") not in valid_strategies:
                violations.append(f"LLM invented remediation strategy: {opt.get('strategy')}")

    # Check 3: LLM must not claim a conflict is not a problem
    dismissive_phrases = [
        "not really a problem",
        "can be safely ignored",
        "not a real conflict",
        "doesn't actually matter",
        "technically compatible",
    ]
    summary = explanation.overall_summary.lower()
    for phrase in dismissive_phrases:
        if phrase in summary:
            violations.append(f"LLM dismissed a conflict with phrase: '{phrase}'")

    # Check 4: Ambiguous license classifications must have confidence
    for amb in explanation.ambiguous_licenses:
        confidence = amb.get("confidence", 0)
        likely = amb.get("likely_spdx")
        if likely and confidence < 0.7:
            # LLM asserted an SPDX id with low confidence — this is fine
            # but flag if it's a GPL-2.0 vs GPL-2.0-or-later distinction
            if "GPL-2.0" in (likely or ""):
                violations.append(
                    f"LLM classified ambiguous text as {likely} with confidence "
                    f"{confidence} — GPL version distinction requires human review"
                )

    return violations


def _parse_llm_response(raw: str) -> LLMExplanation:
    """Parse the LLM's JSON response into a structured object."""
    try:
        # Strip markdown code fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

        data = json.loads(cleaned)
        return LLMExplanation(
            conflict_explanations=data.get("conflict_explanations", []),
            remediation_rankings=data.get("remediation_rankings", []),
            ambiguous_licenses=data.get("ambiguous_licenses", []),
            overall_summary=data.get("overall_summary", ""),
            raw_response=raw,
        )
    except (json.JSONDecodeError, KeyError):
        logger.warning("Failed to parse LLM response as JSON")
        return LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary=raw[:500] if raw else "LLM response could not be parsed.",
            raw_response=raw,
        )


def _generate_stub_explanation(scan_result: ScanResult) -> LLMExplanation:
    """Generate a deterministic stub when LLM is unavailable.

    This ensures the pipeline works end-to-end without an API key.
    The stub provides factual descriptions derived from the conflict data itself.
    """
    explanations = []
    rankings = []

    for conflict in scan_result.conflicts:
        explanations.append(
            {
                "conflict_id": conflict.id,
                "plain_language": (
                    f"The dependency '{conflict.source_node}' is licensed under "
                    f"{conflict.source_license}, which is incompatible with your project's "
                    f"{conflict.target_license} license when distributed as "
                    f"{conflict.distribution_type.value}."
                ),
                "severity_context": (
                    f"Risk severity is {conflict.risk_severity:.2f}/1.0. " f"{conflict.description}"
                ),
            }
        )

        conflict_remediations = [
            r for r in scan_result.remediations if r.conflict_id == conflict.id
        ]
        ranked = []
        for i, rem in enumerate(conflict_remediations, 1):
            ranked.append(
                {
                    "strategy": rem.strategy.value,
                    "rank": i,
                    "engineering_cost_explanation": rem.description,
                    "estimated_effort": _estimate_effort(rem.feasibility),
                }
            )
        rankings.append(
            {
                "conflict_id": conflict.id,
                "ranked_options": ranked,
            }
        )

    n = len(scan_result.conflicts)
    return LLMExplanation(
        conflict_explanations=explanations,
        remediation_rankings=rankings,
        ambiguous_licenses=[],
        overall_summary=(
            f"Found {n} license conflict{'s' if n != 1 else ''} "
            f"in {len(scan_result.dependencies)} dependencies. "
            f"Legal counsel should review before applying any remediations. "
            f"(This is a deterministic summary — LLM was not available.)"
        ),
        raw_response="<stub>",
    )


def _estimate_effort(feasibility: float) -> str:
    if feasibility >= 0.7:
        return "trivial"
    if feasibility >= 0.5:
        return "moderate"
    if feasibility >= 0.3:
        return "significant"
    return "major"
