"""Rendering a record as a one-line, rich-markup-tagged human summary."""

from __future__ import annotations

from interbolt.models.core import Action, Decision, Endorsement, Event, Finding

_ACTION_COLOR = {
    Action.ALLOW: "green",
    Action.BLOCK: "red",
    Action.REQUIRE_APPROVAL: "yellow",
}


def describe_event(event: Event) -> str:
    """Build a one-line, rich-markup-tagged human summary of an `Event`.

    The building block for a custom console/CLI reporter: pass the result
    to a `rich.console.Console.print` (or strip the `[tag]...[/tag]` markup
    for a plain-text sink). Used by `interbolt inspect` internally.

    Args:
        event: The event to describe.

    Returns:
        A rich-markup string summarizing the decision.
    """
    color = _ACTION_COLOR.get(event.decision.action, "white")
    rule = event.decision.matched_rule or "default"
    untrusted = ", ".join(sorted(event.decision.untrusted_sources)) or "-"
    sources = ", ".join(sorted(event.sources)) or "-"
    run_tainted = "[red bold]True[/red bold]" if event.decision.run_tainted else "False"
    return (
        f"{event.decision.tool}  "
        f"[{color}]{event.decision.action.value}[/{color}]  "
        f"rule={rule}  mode={event.decision.mode.value}  "
        f"untrusted_sources={{{untrusted}}}  "
        f"run_tainted={run_tainted}  sources={{{sources}}}"
    )


def describe_decision(decision: Decision) -> str:
    """Build a one-line, rich-markup-tagged human summary of a `Decision`.

    For a caller catching `PolicyViolation`/`ApprovalDenied` (both carry
    `.decision`) or holding a `Decision` returned from `check()` directly:
    a ready-made explanation of what happened and why, without assembling
    one from `matched_rule`/`untrusted_sources`/`matched_condition` by hand.

    Args:
        decision: The decision to describe.

    Returns:
        A rich-markup string summarizing the decision, including the
        matched rule's CEL condition text when one is available.
    """
    color = _ACTION_COLOR.get(decision.action, "white")
    rule = decision.matched_rule or "no match (default sink action)"
    condition = (
        f"  when={decision.matched_condition!r}" if decision.matched_condition else ""
    )
    untrusted = ", ".join(sorted(decision.untrusted_sources)) or "-"
    return (
        f"{decision.tool}  [{color}]{decision.action.value}[/{color}]  "
        f"rule={rule}{condition}  mode={decision.mode.value}  "
        f"untrusted_sources={{{untrusted}}}"
    )


def describe_finding(finding: Finding) -> str:
    """Build a one-line, rich-markup-tagged human summary of a `Finding`.

    Args:
        finding: The finding to describe.

    Returns:
        A rich-markup string summarizing the laundering-audit hit.
    """
    return (
        f"[yellow]finding[/yellow]  source={finding.source}  "
        f"tool={finding.tool}  argument={finding.argument}"
    )


def describe_endorsement(endorsement: Endorsement) -> str:
    """Build a one-line, rich-markup-tagged human summary of an `Endorsement`.

    Args:
        endorsement: The endorsement to describe.

    Returns:
        A rich-markup string summarizing the endorsement.
    """
    lineage = ", ".join(endorsement.lineage) or "-"
    note = f"  note={endorsement.note!r}" if endorsement.note else ""
    return (
        f"[cyan]endorsement[/cyan]  kind={endorsement.kind}  lineage=({lineage}){note}"
    )
