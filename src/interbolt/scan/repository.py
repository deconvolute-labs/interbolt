"""Repository identity, read directly from `.git`. Never a `git` subprocess.

A repository-local `.git/config` can set `core.fsmonitor` or similar to run
an arbitrary command on an ordinary `git` invocation, so shelling out to
`git` inside an untrusted checkout is a code-execution risk. Every field
here is read from the filesystem, bounded, and degrades to `None` on any
failure.
"""

from __future__ import annotations

import re
from pathlib import Path

from interbolt.constants import SCAN_MAX_FILE_BYTES
from interbolt.scan import security
from interbolt.scan.artifact import ScanRepository

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_MAX_PARENT_LEVELS = 64


def locate_repository(scan_root: Path) -> tuple[Path, Path] | None:
    """Locate the repository containing `scan_root`, if any.

    Walks upward from `scan_root` for a `.git` directory or worktree file.
    Exposed separately from `resolve_repository_identity` so a caller can
    also compute `ScanArtifact.scan_root` relative to the repository root.

    Args:
        scan_root: The resolved scan root.

    Returns:
        `(repo_root, git_dir)`: `repo_root` is the directory that directly
        contains `.git`; `git_dir` is where `HEAD`/`config`/refs actually
        live, which differ for a worktree or submodule's `gitdir:` pointer.
        `None` if no `.git` is found.
    """
    return _locate_git_dir(scan_root)


def resolve_repository_identity(
    scan_root: Path, located: tuple[Path, Path] | None
) -> ScanRepository:
    """Resolve repository identity for a scan rooted at `scan_root`.

    Args:
        scan_root: The resolved scan root, used for `root_name` when
            `located` is `None`.
        located: The result of `locate_repository`.

    Returns:
        A `ScanRepository`. Every field but `root_name` is `None` when
        `located` is `None`, or when reading `.git` fails. `root_name`,
        `uri`, and `branch` are all repository-derived (a clone's directory
        name defaults to the remote's advertised repo name, and `.git`'s
        `config`/`HEAD` are themselves part of the untrusted checkout), so
        each is rejected the same way a discovered tool name is: `root_name`
        falls back to a safe placeholder since it is never nullable, `uri`
        and `branch` fall back to `None`.
    """
    if located is None:
        return ScanRepository(
            uri=None, revision=None, branch=None, root_name=_safe_name(scan_root.name)
        )
    repo_root, git_dir = located
    branch, revision = _read_head(git_dir)
    uri = _read_origin_url(git_dir)
    return ScanRepository(
        uri=None if uri is not None and security.is_forbidden_text(uri) else uri,
        revision=revision,
        branch=None
        if branch is not None and security.is_forbidden_text(branch)
        else branch,
        root_name=_safe_name(repo_root.name),
    )


def _safe_name(name: str) -> str:
    """`name`, or a placeholder if it fails the tool-name safety check."""
    return "unnamed" if security.is_forbidden_text(name) else name


def _read_bounded(path: Path) -> str | None:
    """Read a small git-internal file, bounded and degrading to `None`."""
    try:
        if not path.is_file() or path.stat().st_size > SCAN_MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def _locate_git_dir(start: Path) -> tuple[Path, Path] | None:
    """Walk upward from `start` for a `.git` directory or worktree file.

    Returns `(repo_root, git_dir)`: `repo_root` is the directory that
    directly contains `.git` (for `root_name`), `git_dir` is where
    `HEAD`/`config`/refs actually live, which differ for a worktree or
    submodule's `gitdir:`-pointer form.
    """
    current = start
    for _ in range(_MAX_PARENT_LEVELS):
        candidate = current / ".git"
        if candidate.is_dir():
            return current, candidate
        if candidate.is_file():
            pointer = _read_gitdir_pointer(candidate)
            return (current, pointer) if pointer is not None else None
        if current.parent == current:
            return None
        current = current.parent
    return None


def _read_gitdir_pointer(dotgit_file: Path) -> Path | None:
    """Resolve a worktree/submodule `.git` file's `gitdir: <path>` line."""
    content = _read_bounded(dotgit_file)
    if content is None:
        return None
    for line in content.splitlines():
        if line.startswith("gitdir:"):
            pointer = line.removeprefix("gitdir:").strip()
            if not pointer:
                return None
            resolved = (dotgit_file.parent / pointer).resolve(strict=False)
            return resolved if resolved.is_dir() else None
    return None


def _read_head(git_dir: Path) -> tuple[str | None, str | None]:
    """Resolve `(branch, revision)` from `HEAD`. Detached HEAD gives `(None, sha)`."""
    content = _read_bounded(git_dir / "HEAD")
    if content is None:
        return None, None
    content = content.strip()
    if content.startswith("ref:"):
        ref = content.removeprefix("ref:").strip()
        branch = (
            ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else None
        )
        return branch, _resolve_ref(git_dir, ref)
    if _SHA_PATTERN.fullmatch(content):
        return None, content
    return None, None


def _resolve_ref(git_dir: Path, ref: str) -> str | None:
    """Resolve `ref` (e.g. `refs/heads/main`) to a commit SHA, loose or packed."""
    loose = _read_bounded(git_dir / ref)
    if loose is not None:
        candidate = loose.strip()
        if _SHA_PATTERN.fullmatch(candidate):
            return candidate
    return _resolve_packed_ref(git_dir, ref)


def _resolve_packed_ref(git_dir: Path, ref: str) -> str | None:
    """Resolve `ref` from `packed-refs`, git's flat-file ref cache."""
    content = _read_bounded(git_dir / "packed-refs")
    if content is None:
        return None
    for line in content.splitlines():
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        sha, _, name = line.partition(" ")
        if name == ref and _SHA_PATTERN.fullmatch(sha):
            return sha
    return None


def _read_origin_url(git_dir: Path) -> str | None:
    """Read `[remote "origin"]`'s `url` from `config`, normalized."""
    content = _read_bounded(git_dir / "config")
    if content is None:
        return None
    in_origin_section = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_origin_section = line == '[remote "origin"]'
            continue
        if not in_origin_section or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "url":
            url = value.strip()
            return _normalize_git_uri(url) if url else None
    return None


def _normalize_git_uri(url: str) -> str:
    """Drop a trailing `.git` and any userinfo credentials from a remote URL."""
    stripped = url.removesuffix(".git")
    if "://" not in stripped:
        return stripped
    scheme, _, rest = stripped.partition("://")
    authority, sep, path = rest.partition("/")
    _, _, host = authority.rpartition("@")
    return f"{scheme}://{host}{sep}{path}"
