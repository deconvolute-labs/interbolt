"""The `Policy` class: a loaded, compiled policy, and the built-in default."""

from __future__ import annotations

from interbolt.models.core import TrustLevel
from interbolt.policy.compile import CompiledSink, compile_policy
from interbolt.policy.schema import (
    Defaults,
    PolicyDocument,
    compute_policy_fingerprint,
    load_policy_document,
    validate_policy,
)


class Policy:
    """A loaded, compiled policy: the validated document plus its compiled sinks.

    Attributes:
        document: The validated policy document.
        compiled_sinks: Every sink's compiled, ready-to-evaluate rule list.
        source: The filesystem path the policy was loaded from via
            `from_file`, or `None` for a programmatically constructed policy
            (including the built-in default).
        sources_table: The declared source-to-trust mapping, for trust
            resolution at the sink. Computed once here, since `document` is
            frozen and cannot change underneath a live `Policy`.
        id_to_groups: The declared agent-id-to-groups mapping, from the
            policy's optional `agents` section. Computed once here, for the
            same reason as `sources_table`; an agent id absent from it is
            not an error, it resolves to the empty set at read time
            (`resolve_agent_groups`). The table itself never changes after
            construction (`configure()` is the only way a new `Policy`
            comes into existence), but which entry applies is resolved
            fresh on every `check()` call from that call's `agent_id`,
            since one run may span several agents with the acting agent
            chosen per call.
        fingerprint: A stable hash of the normalized document
            (`"sha256:..."`), stamped onto every emitted `Event`/`Finding`/
            `Endorsement` so a record can be joined against the policy that
            produced it, even after the policy has since changed. Computed
            once here, from `document`.
    """

    def __init__(
        self,
        document: PolicyDocument,
        compiled_sinks: dict[str, CompiledSink],
        source: str | None = None,
    ) -> None:
        self.document = document
        self.compiled_sinks = compiled_sinks
        self.source = source
        self.sources_table: dict[str, TrustLevel] = {
            declaration.name: declaration.trust for declaration in document.sources
        }
        self.id_to_groups: dict[str, frozenset[str]] = {
            agent_id: frozenset(declaration.groups)
            for agent_id, declaration in document.agents.items()
        }
        self.fingerprint: str = compute_policy_fingerprint(document)

    @classmethod
    def from_file(cls, path: str) -> Policy:
        """Load, validate, and compile a policy file in one call.

        Args:
            path: Filesystem path to the policy YAML file.

        Returns:
            A `Policy` ready to pass to `configure()`.

        Raises:
            PolicyEvaluationError: If the file is missing, malformed, or
                fails schema or CEL compilation.
        """
        document = load_policy_document(path)
        return cls(
            document=document, compiled_sinks=compile_policy(document), source=path
        )

    @classmethod
    def validate(cls, path: str) -> list[str]:
        """Statically analyze a policy file without loading or compiling it for use.

        Args:
            path: Filesystem path to the policy YAML file.

        Returns:
            A list of human-readable problem descriptions; empty if valid.
            Every error is captured here instead of raised.
        """
        return validate_policy(path)


def default_policy() -> Policy:
    """Return the built-in default policy for programmatic use and testing.

    The default policy declares no sources and no sinks. Undeclared sources
    always resolve to untrusted, and ``defaults.sink_action: require_approval``
    means every guarded call falls through to ``require_approval`` under
    this policy. This is the posture ``configure(policy=None)`` uses when no
    policy is supplied.

    Returns:
        A compiled ``Policy`` representing the built-in default posture.
    """
    document = PolicyDocument(
        version="1.0",
        defaults=Defaults(),
        sources=(),
        sinks={},
    )
    return Policy(document=document, compiled_sinks=compile_policy(document))
