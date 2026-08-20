"""`run` subcommand bodies: `inspect` and its JSONL reader `_load_records`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console

from interbolt import (
    RECORD_TYPE_ENDORSEMENT,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
    Endorsement,
    Event,
    Finding,
)
from interbolt.cli.exit_codes import EXIT_OK, EXIT_USAGE
from interbolt.cli.render import _build_tree, _run_id_of, emit_json


def _load_records(
    path: Path, console: Console, *, emit_warnings: bool = True
) -> list[Event | Finding | Endorsement]:
    """Parse a JSONL file written by `JsonlReporter`.

    Args:
        path: The JSONL file to read.
        console: Where a malformed-line warning is printed.
        emit_warnings: Whether to print malformed-line warnings. Set `False`
            under `--format json`, so a warning never gets interleaved into
            the JSON payload written to the same stream.

    Returns:
        Every successfully parsed `Event`/`Finding`/`Endorsement`, in file
        order. A line that fails to parse as JSON, carries an unrecognized
        or missing `record_type`, or fails model validation is skipped, with
        a warning printed to the console when `emit_warnings` is set, and
        reading continues.
    """
    records: list[Event | Finding | Endorsement] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
                record_type = raw.pop("record_type", None)
                if record_type == RECORD_TYPE_EVENT:
                    records.append(Event.model_validate(raw))
                elif record_type == RECORD_TYPE_FINDING:
                    records.append(Finding.model_validate(raw))
                elif record_type == RECORD_TYPE_ENDORSEMENT:
                    records.append(Endorsement.model_validate(raw))
                else:
                    raise ValueError(f"unrecognized record_type: {record_type!r}")
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                if emit_warnings:
                    console.print(f"[yellow]![/yellow] line {line_number}: {exc}")
    return records


def _record_json(record: Event | Finding | Endorsement) -> dict[str, object]:
    if isinstance(record, Event):
        record_type = RECORD_TYPE_EVENT
    elif isinstance(record, Finding):
        record_type = RECORD_TYPE_FINDING
    else:
        record_type = RECORD_TYPE_ENDORSEMENT
    return {"record_type": record_type, **record.model_dump(mode="json")}


def _inspect(args: argparse.Namespace, console: Console) -> int:
    path = Path(args.path)
    if not path.exists():
        message = f"{path} not found"
        if args.format == "json":
            emit_json(
                console, {"command": "run inspect", "path": str(path), "error": message}
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_USAGE

    all_records = _load_records(path, console, emit_warnings=args.format != "json")
    if not all_records:
        message = f"no records found in {path}"
        if args.format == "json":
            emit_json(
                console, {"command": "run inspect", "path": str(path), "error": message}
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_USAGE

    records = all_records
    if args.run_id is not None:
        records = [r for r in records if _run_id_of(r) == args.run_id]

    if args.format == "json":
        emit_json(
            console,
            {
                "command": "run inspect",
                "path": str(path),
                "run_id": args.run_id,
                "records": [_record_json(r) for r in records],
            },
        )
        return EXIT_OK

    console.print(_build_tree(records))
    if not args.quiet:
        console.print(f"[green]✓[/green] rendered {len(records)} record(s) from {path}")
    return EXIT_OK
