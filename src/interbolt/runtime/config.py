"""configure(): mode precedence, env parsing, and the default approval resolver."""

from __future__ import annotations

import os
import sys

from interbolt.constants import ENV_AUDIT, ENV_MODE
from interbolt.enforcement import AuditRegistry
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Decision, Mode
from interbolt.models.protocols import ApprovalResolver, Reporter
from interbolt.policy import Policy
from interbolt.policy import default_policy as _default_policy
from interbolt.reporting import NullReporter
from interbolt.runtime.current import _set_current
from interbolt.runtime.observers import make_audit_observer, make_endorsement_emitter
from interbolt.runtime.runtime import Runtime
from interbolt.taint import install_endorsement_emitter, install_taint_observer
from interbolt.utils import get_logger

_logger = get_logger("runtime")


def auto_deny(decision: Decision) -> bool:
    """The default `ApprovalResolver`: deny every approval request.

    Args:
        decision: The decision that requires approval.

    Returns:
        Always `False`.
    """
    return False


def _parse_mode(value: Mode | str, *, source: str) -> Mode:
    try:
        return Mode(value)
    except ValueError as exc:
        raise InterboltConfigError(f"{source}={value!r} is not a valid mode") from exc


def _caller_location() -> tuple[str, int]:
    """Return the (filename, lineno) of configure()'s caller.

    Uses `sys._getframe` (CPython-specific, guarded with a fallback) rather
    than `inspect.stack()`, which walks and resolves the entire call stack,
    including reading source context lines, just to extract one frame.
    """
    try:
        frame = sys._getframe(2)
        return frame.f_code.co_filename, frame.f_lineno
    except AttributeError:
        return "unknown", 0


def configure(
    *,
    policy: Policy | None = None,
    reporter: Reporter | None = None,
    approval_resolver: ApprovalResolver = auto_deny,
    mode: Mode | str = Mode.ENFORCE,
    audit: bool = False,
) -> Runtime:
    """Build the runtime and install it as the one this process uses.

    Call this once at startup, before the first guarded call. Policy
    compilation happens here; importing a module that uses `@guard` does not
    require `configure()` to have run.

    The effective mode comes from the first of these that is set:

    1. The `INTERBOLT_MODE` environment variable.
    2. The policy file's `defaults.fail_mode`.
    3. The `mode` argument.

    `INTERBOLT_AUDIT` overrides `audit` the same way. Each call logs one
    summary line at INFO with the effective mode, the policy source, and the
    source and sink counts, so the active configuration is visible without a
    reporter attached.

    Args:
        policy: The policy to enforce. With `None`, a built-in policy that
            declares no sources and no sinks is used, so every guarded call
            needs approval. Run `interbolt init` to generate a real one.
        reporter: Where decisions and findings go. Defaults to `NullReporter`.
        approval_resolver: Decides `require_approval` calls. Defaults to
            `auto_deny`.
        mode: `enforce`, `monitor`, or `dry_run`. Lowest precedence of the
            three sources above.
        audit: Whether to look for untrusted content reaching a sink without a
            mark. Findings go to the reporter. Off by default.

    Returns:
        The configured `Runtime`.

    Raises:
        InterboltConfigError: If the effective mode is not one of the three
            valid values.
    """
    # configure() is the only function that installs process-global state.
    # The complete set: the process-current runtime (current._set_current,
    # below), the taint()-time audit observer and the endorse()-time
    # emitter (both taint/-owned hooks; see taint/runstate.py), and,
    # implicitly as a data sink populated regardless of whether configure()
    # has ever run, the run-ingress registry (also in taint/runstate.py).
    policy_was_given = policy is not None
    if policy is None:
        policy = _default_policy()

    resolved_mode = _parse_mode(mode, source="mode")
    if policy.document.defaults.fail_mode is not None:
        if policy.document.defaults.fail_mode != resolved_mode:
            _logger.warning(
                "policy defaults.fail_mode=%r overrides mode=%r",
                policy.document.defaults.fail_mode.value,
                resolved_mode.value,
            )
        resolved_mode = policy.document.defaults.fail_mode

    env_mode = os.environ.get(ENV_MODE)
    if env_mode is not None:
        parsed_env_mode = _parse_mode(env_mode, source=ENV_MODE)
        if parsed_env_mode != resolved_mode:
            _logger.warning(
                "%s=%r overrides effective mode=%r",
                ENV_MODE,
                env_mode,
                resolved_mode,
            )
        resolved_mode = parsed_env_mode

    env_audit = os.environ.get(ENV_AUDIT)
    if env_audit is not None:
        audit = env_audit.strip().lower() in {"1", "true", "yes", "on"}

    audit_registry = AuditRegistry() if audit else None
    runtime = Runtime(
        policy=policy,
        reporter=reporter or NullReporter(),
        approval_resolver=approval_resolver,
        mode=resolved_mode,
        audit_registry=audit_registry,
    )
    _set_current(runtime)

    if audit_registry is not None:
        install_taint_observer(make_audit_observer(policy, audit_registry))
    else:
        install_taint_observer(None)

    install_endorsement_emitter(make_endorsement_emitter(runtime))

    if not policy_was_given:
        _logger.warning(
            "configure(): no policy given; using the built-in default policy "
            "(no sources, no sinks, every guarded call falls through to "
            "require_approval); run `interbolt init` to generate a policy file"
        )

    caller_file, caller_line = _caller_location()

    _logger.info(
        "configure(): mode=%s policy_source=%s sources=%d sinks=%d audit=%s "
        "caller=%s:%d",
        resolved_mode.value,
        policy.source or "programmatic (no file; interbolt init to generate one)",
        len(policy.document.sources),
        len(policy.document.sinks),
        audit,
        caller_file,
        caller_line,
    )
    return runtime
