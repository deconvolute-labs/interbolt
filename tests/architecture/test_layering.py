"""The layering rule, enforced instead of remembered.

Imports point inward along the order below. A module that reaches outward,
or a cycle, fails here rather than in review.
"""

from __future__ import annotations

import ast
import pathlib

SRC = pathlib.Path(__file__).parents[2] / "src" / "interbolt"

# Inward to outward. A module may import its own layer or anything above it.
LAYERS = (
    ("errors", "constants", "utils"),
    ("models",),
    ("taint", "policy"),
    ("enforcement", "scan"),
    ("reporting",),
    ("runtime",),
    ("cli", "integrations"),
)
RANK = {name: i for i, layer in enumerate(LAYERS) for name in layer}

# errors.py references Decision under TYPE_CHECKING only; cli/ and reporting/
# may read the package root for the public surface and __version__.
ALLOWED_OUTWARD = {("errors", "models")}


def _layer(module: str) -> str | None:
    parts = module.split(".")
    return parts[1] if len(parts) > 1 and parts[1] in RANK else None


def test_no_module_imports_outward() -> None:
    violations = []
    for path in sorted(SRC.rglob("*.py")):
        module = "interbolt." + str(path.relative_to(SRC))[:-3].replace("/", ".")
        source = _layer(module.removesuffix(".__init__"))
        if source is None:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not node.module or not node.module.startswith("interbolt"):
                continue
            target = _layer(node.module)
            if target is None or target == source:
                continue
            if RANK[source] < RANK[target] and (source, target) not in ALLOWED_OUTWARD:
                violations.append(f"{module} imports {node.module}")
    assert not violations, "outward imports: " + "; ".join(violations)
