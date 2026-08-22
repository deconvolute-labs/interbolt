"""`scan/signature.py`: parameter-list and return-annotation rendering (§6.2)."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.signature import render_signature


def _function(source: str) -> ast.FunctionDef:
    tree = ast.parse(textwrap.dedent(source))
    node = tree.body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


class TestRenderSignature:
    def test_simple_annotated_params_and_return(self) -> None:
        node = _function("def f(to: str, body: str) -> None: ...")
        assert render_signature(node) == "(to: str, body: str) -> None"

    def test_no_annotations_at_all(self) -> None:
        node = _function("def f(to, body): ...")
        assert render_signature(node) == "(to, body)"

    def test_no_return_annotation(self) -> None:
        node = _function("def f(to: str): ...")
        assert render_signature(node) == "(to: str)"

    def test_plain_constant_defaults_rendered(self) -> None:
        node = _function(
            'def f(cc: str = "a@b.com", retries: int = 3, '
            "dry_run: bool = False, note=None) -> None: ..."
        )
        assert render_signature(node) == (
            "(cc: str = 'a@b.com', retries: int = 3, "
            "dry_run: bool = False, note = None) -> None"
        )

    def test_non_constant_default_dropped_parameter_still_renders(self) -> None:
        node = _function("def f(to: str, ref=make_id()) -> None: ...")
        assert render_signature(node) == "(to: str, ref) -> None"

    def test_positional_only_separator(self) -> None:
        node = _function("def f(to, /, body: str) -> None: ...")
        assert render_signature(node) == "(to, /, body: str) -> None"

    def test_varargs_and_kwargs_with_annotations(self) -> None:
        node = _function("def f(to: str, *tags: str, **extra: int) -> None: ...")
        assert render_signature(node) == "(to: str, *tags: str, **extra: int) -> None"

    def test_keyword_only_without_star_args_gets_bare_star(self) -> None:
        node = _function('def f(to: str, *, subject: str = "hi", body) -> None: ...')
        assert (
            render_signature(node) == "(to: str, *, subject: str = 'hi', body) -> None"
        )

    def test_keyword_only_after_star_args_no_bare_star(self) -> None:
        node = _function('def f(*tags: str, subject: str = "hi") -> None: ...')
        assert render_signature(node) == "(*tags: str, subject: str = 'hi') -> None"

    def test_async_def_supported(self) -> None:
        node = ast.parse("async def f(to: str) -> None: ...").body[0]
        assert isinstance(node, ast.AsyncFunctionDef)
        assert render_signature(node) == "(to: str) -> None"

    def test_bidi_override_in_string_default_is_escaped_not_raw(self) -> None:
        bidi = "‮"  # RIGHT-TO-LEFT OVERRIDE, the Trojan Source character
        node = _function(f'def f(cc: str = "a{bidi}b") -> None: ...')
        signature = render_signature(node)
        # ast.unparse renders a string Constant through the same
        # repr()-style escaping Python uses for any non-printable
        # character, so the bidi override never reaches the artifact raw.
        # This is what makes the field safe without the scanner having to
        # special-case string defaults itself.
        assert signature == "(cc: str = 'a\\u202eb') -> None"
        assert bidi not in signature


class TestDefenseInDepth:
    def test_forbidden_character_in_a_synthetic_node_is_rejected(self) -> None:
        # A real parameter name can never contain a bidi/control character
        # (Python's grammar excludes it per PEP 3131), so this hand-builds
        # an AST no `ast.parse` call could produce, purely to confirm the
        # is_forbidden_text backstop in render_signature actually rejects
        # what it claims to, even though real parsed source can't reach it.
        bidi = "‮"
        node = ast.FunctionDef(
            name="f",
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=f"to{bidi}evil", annotation=None)],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=[ast.Pass()],
            decorator_list=[],
            returns=None,
            type_params=[],
        )
        ast.fix_missing_locations(node)
        assert render_signature(node) is None
