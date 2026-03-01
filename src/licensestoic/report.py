"""Terminal UI and structured report output — Observability layer.

Provides:
1. Rich terminal output with severity bars, conflict details, and remediation suggestions
2. JSON structured report for CI/CD integration
3. Reliability curve warnings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from licensestoic.llm_explainer import LLMExplanation
from licensestoic.models import Conflict, IntegrationType, ReviewAction, ScanResult
from licensestoic.review_gate import classify_conflict, generate_review_summary

console = Console()

# Severity bar rendering
_BAR_CHARS = 10


def _severity_bar(severity: float) -> str:
    filled = round(severity * _BAR_CHARS)
    return "#" * filled + "." * (_BAR_CHARS - filled)


def _severity_color(severity: float) -> str:
    if severity >= 0.7:
        return "red"
    if severity >= 0.4:
        return "yellow"
    return "green"


def _action_label(action: ReviewAction) -> tuple[str, str]:
    labels = {
        ReviewAction.ESCALATE: ("ESCALATE", "red"),
        ReviewAction.SUGGEST: ("SUGGEST", "yellow"),
        ReviewAction.AUTO_APPLY: ("AUTO", "green"),
    }
    return labels.get(action, ("UNKNOWN", "white"))


def render_terminal_report(
    scan_result: ScanResult,
    explanation: LLMExplanation | None = None,
) -> None:
    """Render a rich terminal report."""
    # Header
    console.print()
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan")
    header.add_column()
    header.add_row(
        "Project:", f"{scan_result.project_name} ({scan_result.project_license.spdx_expression})"
    )
    header.add_row("Distribution:", scan_result.distribution_type.value)
    header.add_row("Dependencies scanned:", str(len(scan_result.dependencies)))
    header.add_row("Scan confidence:", f"{scan_result.scan_confidence:.2f}")

    console.print(Panel(header, title="LicenseStoic — Scan Report", border_style="cyan"))

    # Conflicts
    if not scan_result.conflicts:
        # Distinguish genuinely clean scan from inconclusive scan
        _non_dev_integrations = frozenset(
            {IntegrationType.BUILD_TOOL, IntegrationType.TEST_ONLY, IntegrationType.DEV_ONLY}
        )
        non_dev_deps = [
            d for d in scan_result.dependencies if d.integration_type not in _non_dev_integrations
        ]
        unknown_deps = [d for d in non_dev_deps if not d.license_expression.identifiers]

        if unknown_deps and non_dev_deps:
            pct = len(unknown_deps) / len(non_dev_deps) * 100
            if pct > 50:
                console.print(
                    Panel(
                        f"[bold yellow]Scan inconclusive:[/] {len(unknown_deps)} of "
                        f"{len(non_dev_deps)} dependencies ({pct:.0f}%) have unknown licenses.\n"
                        f"Install the project's dependencies and re-scan for accurate results.",
                        border_style="yellow",
                    )
                )
            else:
                console.print(
                    Panel(
                        f"[bold green]No license conflicts detected[/] among known licenses.\n"
                        f"[yellow]{len(unknown_deps)} dependency(ies) have unknown licenses "
                        f"and could not be verified.[/]",
                        border_style="green",
                    )
                )
        else:
            console.print(
                Panel("[bold green]No license conflicts detected.[/]", border_style="green")
            )
    else:
        console.print(
            f"\n[bold]CONFLICTS ({len(scan_result.conflicts)} found)[/]",
        )
        console.print("-" * 60)

        for conflict in scan_result.conflicts:
            _render_conflict(conflict, explanation)

    # Reliability warnings
    if scan_result.reliability_warnings:
        console.print("\n[bold yellow]RELIABILITY WARNINGS[/]")
        console.print("-" * 60)
        for warning in scan_result.reliability_warnings:
            console.print(f"  [yellow]![/] {warning.message}")

    # Remediations
    if scan_result.remediations:
        console.print("\n[bold]REMEDIATIONS[/]")
        console.print("-" * 60)
        for i, rem in enumerate(scan_result.remediations, 1):
            effort = ""
            if rem.engineering_cost_rank:
                effort = f" (rank #{rem.engineering_cost_rank})"
            console.print(f"  [{i}] {rem.description}{effort}")

    # Overall summary
    if explanation and explanation.overall_summary:
        console.print()
        console.print(
            Panel(
                explanation.overall_summary,
                title="Summary",
                border_style="blue",
            )
        )

    # Review action
    review = scan_result.review_action
    label, color = _action_label(review)
    console.print(f"\n[bold]Overall review action:[/] [{color}]{label}[/{color}]")
    console.print()


def _render_conflict(conflict: Conflict, explanation: LLMExplanation | None) -> None:
    """Render a single conflict with severity bar."""
    color = _severity_color(conflict.risk_severity)
    action = classify_conflict(conflict)
    action_label, action_color = _action_label(action)
    bar = _severity_bar(conflict.risk_severity)

    console.print(
        f"  [{color}]{bar}[/] {conflict.risk_severity:.2f}  "
        f"{conflict.source_node} ({conflict.source_license})  "
        f"[{action_color}][{action_label}][/{action_color}]"
    )
    console.print(
        f"           -> {conflict.integration_type.value} -> project "
        f"({conflict.target_license})"
    )
    if conflict.transitive_chain and len(conflict.transitive_chain) > 1:
        chain_str = " -> ".join(conflict.transitive_chain)
        console.print(f"           -> chain: {chain_str}")

    # LLM explanation if available
    if explanation:
        for expl in explanation.conflict_explanations:
            if expl.get("conflict_id") == conflict.id:
                console.print(f"           [dim]{expl.get('plain_language', '')}[/dim]")
                break

    console.print()


def generate_json_report(
    scan_result: ScanResult,
    explanation: LLMExplanation | None = None,
) -> dict[str, Any]:
    """Generate a structured JSON report for CI/CD and audit trails."""
    review = generate_review_summary(scan_result)

    report = {
        "version": "1.0.0",
        "project": {
            "name": scan_result.project_name,
            "license": scan_result.project_license.model_dump(),
            "distribution_type": scan_result.distribution_type.value,
        },
        "scan": {
            "confidence": scan_result.scan_confidence,
            "total_dependencies": len(scan_result.dependencies),
            "total_conflicts": len(scan_result.conflicts),
        },
        "conflicts": [c.model_dump() for c in scan_result.conflicts],
        "remediations": [r.model_dump() for r in scan_result.remediations],
        "review": review,
        "reliability_warnings": [w.model_dump() for w in scan_result.reliability_warnings],
    }

    if explanation:
        report["llm_explanation"] = {
            "conflict_explanations": explanation.conflict_explanations,
            "remediation_rankings": explanation.remediation_rankings,
            "ambiguous_licenses": explanation.ambiguous_licenses,
            "overall_summary": explanation.overall_summary,
        }

    return report


def save_json_report(
    scan_result: ScanResult,
    output_path: str | Path,
    explanation: LLMExplanation | None = None,
) -> Path:
    """Save the structured JSON report to a file."""
    output = Path(output_path)
    report = generate_json_report(scan_result, explanation)
    output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return output
