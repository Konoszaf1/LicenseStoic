"""Adversarial validation tests for the LLM explanation layer.

These tests verify that the AIQA boundary enforcement works:
1. The LLM output validator catches violations
2. Stub explanations are compliant
3. Various attack patterns are detected

This is the demonstration of AIQA prowess — the system structurally prevents
the LLM from making unauthorized decisions.
"""

from licensestoic.llm_explainer import (
    LLMExplanation,
    _generate_stub_explanation,
    validate_llm_output,
)
from licensestoic.models import (
    Conflict,
    DistributionType,
    IntegrationType,
    LicenseExpression,
    RemediationOption,
    RemediationStrategy,
    ReviewAction,
    ScanResult,
)


def _make_scan_result_with_conflict() -> ScanResult:
    """Create a ScanResult with one GPL conflict for testing."""
    return ScanResult(
        project_name="test-project",
        project_license=LicenseExpression(
            spdx_expression="MIT",
            identifiers=["MIT"],
            is_valid_spdx=True,
        ),
        distribution_type=DistributionType.BINARY,
        dependencies=[],
        conflicts=[
            Conflict(
                id="conflict-gpl-dep-GPL-3.0-only",
                source_node="gpl-dep",
                target_node="project",
                source_license="GPL-3.0-only",
                target_license="MIT",
                distribution_type=DistributionType.BINARY,
                integration_type=IntegrationType.STATIC_LINK,
                risk_severity=0.85,
                rule_source="builtin_matrix",
                description="GPL-3.0-only incompatible with MIT for binary distribution.",
            ),
        ],
        remediations=[
            RemediationOption(
                conflict_id="conflict-gpl-dep-GPL-3.0-only",
                strategy=RemediationStrategy.REPLACE_DEPENDENCY,
                description="Replace gpl-dep with a compatible alternative.",
                feasibility=0.6,
            ),
            RemediationOption(
                conflict_id="conflict-gpl-dep-GPL-3.0-only",
                strategy=RemediationStrategy.REMOVE_DEPENDENCY,
                description="Remove gpl-dep.",
                feasibility=0.2,
            ),
        ],
        scan_confidence=1.0,
        review_action=ReviewAction.ESCALATE,
    )


class TestStubExplanationCompliance:
    """The deterministic stub must always pass validation."""

    def test_stub_passes_validation(self):
        scan = _make_scan_result_with_conflict()
        stub = _generate_stub_explanation(scan)
        violations = validate_llm_output(stub, scan)
        assert violations == [], f"Stub explanation violated boundaries: {violations}"

    def test_stub_references_only_real_conflicts(self):
        scan = _make_scan_result_with_conflict()
        stub = _generate_stub_explanation(scan)
        valid_ids = {c.id for c in scan.conflicts}
        for expl in stub.conflict_explanations:
            assert expl["conflict_id"] in valid_ids

    def test_stub_references_only_real_strategies(self):
        scan = _make_scan_result_with_conflict()
        stub = _generate_stub_explanation(scan)
        valid_strategies = {r.strategy.value for r in scan.remediations}
        for ranking in stub.remediation_rankings:
            for opt in ranking["ranked_options"]:
                assert opt["strategy"] in valid_strategies


class TestLLMViolationDetection:
    """Test that the validator catches specific violation patterns."""

    def test_catches_phantom_conflict_reference(self):
        """LLM references a conflict that doesn't exist."""
        scan = _make_scan_result_with_conflict()
        bad_explanation = LLMExplanation(
            conflict_explanations=[
                {
                    "conflict_id": "conflict-DOES-NOT-EXIST",
                    "plain_language": "This is a fake conflict.",
                    "severity_context": "Made up.",
                }
            ],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary="Everything is fine.",
            raw_response="{}",
        )
        violations = validate_llm_output(bad_explanation, scan)
        assert any("non-existent conflict" in v for v in violations)

    def test_catches_invented_strategy(self):
        """LLM invents a remediation strategy that wasn't pre-validated."""
        scan = _make_scan_result_with_conflict()
        bad_explanation = LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[
                {
                    "conflict_id": "conflict-gpl-dep-GPL-3.0-only",
                    "ranked_options": [
                        {
                            "strategy": "ignore_and_hope_for_the_best",
                            "rank": 1,
                            "engineering_cost_explanation": "Just ignore it.",
                            "estimated_effort": "trivial",
                        }
                    ],
                }
            ],
            ambiguous_licenses=[],
            overall_summary="You can safely ignore this.",
            raw_response="{}",
        )
        violations = validate_llm_output(bad_explanation, scan)
        assert any("invented remediation" in v for v in violations)

    def test_catches_dismissive_language(self):
        """LLM claims a conflict can be safely ignored."""
        scan = _make_scan_result_with_conflict()
        bad_explanation = LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[],
            ambiguous_licenses=[],
            overall_summary="This conflict is not really a problem and can be safely ignored.",
            raw_response="{}",
        )
        violations = validate_llm_output(bad_explanation, scan)
        assert len(violations) >= 1
        assert any("dismissed" in v for v in violations)

    def test_catches_gpl_version_ambiguity(self):
        """LLM classifies ambiguous text as GPL-2.0 with low confidence."""
        scan = _make_scan_result_with_conflict()
        bad_explanation = LLMExplanation(
            conflict_explanations=[],
            remediation_rankings=[],
            ambiguous_licenses=[
                {
                    "raw_text": "GNU General Public License",
                    "likely_spdx": "GPL-2.0-only",
                    "confidence": 0.4,
                    "reasoning": "Probably GPL 2.",
                }
            ],
            overall_summary="Found ambiguous licenses.",
            raw_response="{}",
        )
        violations = validate_llm_output(bad_explanation, scan)
        assert any("GPL version distinction" in v for v in violations)


class TestCleanLLMOutputPasses:
    """A well-behaved LLM response should pass validation."""

    def test_compliant_explanation_passes(self):
        scan = _make_scan_result_with_conflict()
        good_explanation = LLMExplanation(
            conflict_explanations=[
                {
                    "conflict_id": "conflict-gpl-dep-GPL-3.0-only",
                    "plain_language": (
                        "The dependency 'gpl-dep' uses GPL-3.0, which requires "
                        "your entire project to be open-sourced under GPL-3.0 if "
                        "distributed as a binary. This conflicts with your MIT license."
                    ),
                    "severity_context": (
                        "High severity (0.85) because GPL-3.0 with static linking "
                        "in a binary distribution creates strong copyleft obligations."
                    ),
                }
            ],
            remediation_rankings=[
                {
                    "conflict_id": "conflict-gpl-dep-GPL-3.0-only",
                    "ranked_options": [
                        {
                            "strategy": "replace_dependency",
                            "rank": 1,
                            "engineering_cost_explanation": (
                                "Find an MIT or Apache-2.0 alternative."
                            ),
                            "estimated_effort": "moderate",
                        },
                        {
                            "strategy": "remove_dependency",
                            "rank": 2,
                            "engineering_cost_explanation": ("Reimplement the functionality."),
                            "estimated_effort": "major",
                        },
                    ],
                }
            ],
            ambiguous_licenses=[],
            overall_summary=(
                "Found 1 license conflict. The GPL-3.0 dependency is incompatible "
                "with the MIT project license for binary distribution. "
                "Legal counsel should review before applying remediations."
            ),
            raw_response="{}",
        )
        violations = validate_llm_output(good_explanation, scan)
        assert violations == []


# ---------------------------------------------------------------------------
# LLM response parsing tests
# ---------------------------------------------------------------------------


class TestParseLlmResponse:
    """Test _parse_llm_response JSON extraction."""

    def test_valid_json(self):
        from licensestoic.llm_explainer import _parse_llm_response

        raw = (
            '{"conflict_explanations": [], "remediation_rankings": [], '
            '"ambiguous_licenses": [], "overall_summary": "All clear."}'
        )
        result = _parse_llm_response(raw)
        assert result.overall_summary == "All clear."
        assert result.conflict_explanations == []
        assert result.raw_response == raw

    def test_json_with_markdown_fences(self):
        from licensestoic.llm_explainer import _parse_llm_response

        raw = (
            "```json\n"
            '{"conflict_explanations": [], "remediation_rankings": [], '
            '"ambiguous_licenses": [], "overall_summary": "Fenced."}\n'
            "```"
        )
        result = _parse_llm_response(raw)
        assert result.overall_summary == "Fenced."

    def test_malformed_json_returns_fallback(self):
        from licensestoic.llm_explainer import _parse_llm_response

        result = _parse_llm_response("this is not json at all")
        assert result.conflict_explanations == []
        assert result.remediation_rankings == []
        assert "this is not json" in result.overall_summary

    def test_empty_string_returns_fallback(self):
        from licensestoic.llm_explainer import _parse_llm_response

        result = _parse_llm_response("")
        assert result.overall_summary == "LLM response could not be parsed."

    def test_partial_json_uses_defaults(self):
        from licensestoic.llm_explainer import _parse_llm_response

        result = _parse_llm_response('{"overall_summary": "partial"}')
        assert result.overall_summary == "partial"
        assert result.conflict_explanations == []


# ---------------------------------------------------------------------------
# LLM prompt construction tests
# ---------------------------------------------------------------------------


class TestBuildLlmPrompt:
    """Test that build_llm_prompt produces well-formed prompts."""

    def test_includes_project_metadata(self):
        from licensestoic.llm_explainer import build_llm_prompt

        scan = _make_scan_result_with_conflict()
        prompt = build_llm_prompt(scan)

        assert "test-project" in prompt
        assert "MIT" in prompt
        assert "binary" in prompt

    def test_includes_conflict_data(self):
        from licensestoic.llm_explainer import build_llm_prompt

        scan = _make_scan_result_with_conflict()
        prompt = build_llm_prompt(scan)

        assert "GPL-3.0-only" in prompt
        assert "gpl-dep" in prompt

    def test_includes_remediation_data(self):
        from licensestoic.llm_explainer import build_llm_prompt

        scan = _make_scan_result_with_conflict()
        prompt = build_llm_prompt(scan)

        assert "replace_dependency" in prompt
        assert "remove_dependency" in prompt

    def test_no_ambiguous_section_when_all_valid(self):
        from licensestoic.llm_explainer import build_llm_prompt

        scan = _make_scan_result_with_conflict()
        prompt = build_llm_prompt(scan)

        assert "Ambiguous license texts" not in prompt


class TestEstimateEffort:
    """Test the _estimate_effort mapping."""

    def test_high_feasibility_trivial(self):
        from licensestoic.llm_explainer import _estimate_effort

        assert _estimate_effort(0.8) == "trivial"

    def test_medium_feasibility_moderate(self):
        from licensestoic.llm_explainer import _estimate_effort

        assert _estimate_effort(0.5) == "moderate"

    def test_low_feasibility_significant(self):
        from licensestoic.llm_explainer import _estimate_effort

        assert _estimate_effort(0.3) == "significant"

    def test_very_low_feasibility_major(self):
        from licensestoic.llm_explainer import _estimate_effort

        assert _estimate_effort(0.1) == "major"


class TestMultipleSimultaneousViolations:
    """Verify the validator catches multiple violations in a single response."""

    def test_phantom_and_invented_and_dismissive(self):
        scan = _make_scan_result_with_conflict()
        bad_explanation = LLMExplanation(
            conflict_explanations=[
                {
                    "conflict_id": "conflict-FAKE",
                    "plain_language": "Fake.",
                    "severity_context": "Fake.",
                }
            ],
            remediation_rankings=[
                {
                    "conflict_id": "conflict-gpl-dep-GPL-3.0-only",
                    "ranked_options": [
                        {
                            "strategy": "magic_fix",
                            "rank": 1,
                            "engineering_cost_explanation": "Magic.",
                            "estimated_effort": "trivial",
                        }
                    ],
                }
            ],
            ambiguous_licenses=[],
            overall_summary="This conflict is not really a problem.",
            raw_response="{}",
        )
        violations = validate_llm_output(bad_explanation, scan)
        assert len(violations) >= 3
        assert any("non-existent conflict" in v for v in violations)
        assert any("invented remediation" in v for v in violations)
        assert any("dismissed" in v for v in violations)
