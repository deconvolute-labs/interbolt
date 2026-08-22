"""`scan/repository.py`: git identity read directly from `.git`, never a subprocess."""

from __future__ import annotations

from pathlib import Path

from pytest_mock import MockerFixture

from interbolt.scan.repository import locate_repository, resolve_repository_identity


def _init_git_dir(repo: Path, *, branch: str = "main") -> Path:
    git_dir = repo / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text(f"ref: refs/heads/{branch}\n")
    (git_dir / "refs" / "heads").mkdir(parents=True)
    return git_dir


class TestNoSubprocess:
    def test_repository_module_never_imports_subprocess(self) -> None:
        import ast

        import interbolt.scan.repository as module

        source = Path(module.__file__).read_text()
        imported = {
            alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert "subprocess" not in imported

    def test_resolving_identity_never_calls_subprocess_run(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        spy = mocker.patch("subprocess.run")
        git_dir = _init_git_dir(tmp_path)
        sha = "a" * 40
        (git_dir / "refs" / "heads" / "main").write_text(sha + "\n")
        located = locate_repository(tmp_path)
        resolve_repository_identity(tmp_path, located)
        spy.assert_not_called()


class TestNoGitFound:
    def test_degrades_to_all_none_except_root_name(self, tmp_path: Path) -> None:
        located = locate_repository(tmp_path)
        assert located is None
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.uri is None
        assert repo.revision is None
        assert repo.branch is None
        assert repo.root_name == tmp_path.name


class TestLooseRef:
    def test_branch_and_revision_from_loose_ref(self, tmp_path: Path) -> None:
        git_dir = _init_git_dir(tmp_path, branch="main")
        sha = "b" * 40
        (git_dir / "refs" / "heads" / "main").write_text(sha + "\n")
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.branch == "main"
        assert repo.revision == sha
        assert repo.root_name == tmp_path.name


class TestPackedRefs:
    def test_branch_resolved_from_packed_refs_when_no_loose_ref(
        self, tmp_path: Path
    ) -> None:
        git_dir = _init_git_dir(tmp_path, branch="main")
        sha = "c" * 40
        (git_dir / "packed-refs").write_text(
            f"# pack-refs with: peeled fully-peeled sorted\n{sha} refs/heads/main\n"
        )
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.branch == "main"
        assert repo.revision == sha


class TestDetachedHead:
    def test_detached_head_has_no_branch(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        sha = "d" * 40
        (git_dir / "HEAD").write_text(sha + "\n")
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.branch is None
        assert repo.revision == sha


class TestOriginUrl:
    def test_uri_normalized_drops_credentials_and_git_suffix(
        self, tmp_path: Path
    ) -> None:
        git_dir = _init_git_dir(tmp_path)
        (git_dir / "config").write_text(
            '[remote "origin"]\n'
            "\turl = https://user:token@github.com/acme/support-agent.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.uri == "https://github.com/acme/support-agent"

    def test_no_origin_section_gives_none(self, tmp_path: Path) -> None:
        git_dir = _init_git_dir(tmp_path)
        (git_dir / "config").write_text("[core]\n\tbare = false\n")
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.uri is None


class TestWorktreePointer:
    def test_dotgit_file_gitdir_pointer_followed(self, tmp_path: Path) -> None:
        real_git = tmp_path / "real.git"
        real_git.mkdir()
        (real_git / "HEAD").write_text("ref: refs/heads/main\n")
        (real_git / "refs" / "heads").mkdir(parents=True)
        sha = "e" * 40
        (real_git / "refs" / "heads" / "main").write_text(sha + "\n")

        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".git").write_text(f"gitdir: {real_git}\n")

        located = locate_repository(worktree)
        assert located is not None
        repo_root, git_dir = located
        assert repo_root == worktree
        assert git_dir == real_git.resolve()
        repo = resolve_repository_identity(worktree, located)
        assert repo.branch == "main"
        assert repo.revision == sha
        assert repo.root_name == "worktree"


class TestUnsafeStringsRejected:
    def test_bidi_root_name_replaced_with_placeholder(self, tmp_path: Path) -> None:
        evil = tmp_path / ("repo" + "‮" + "evil")
        evil.mkdir()
        located = locate_repository(evil)
        assert located is None
        repo = resolve_repository_identity(evil, located)
        assert repo.root_name == "unnamed"

    def test_bidi_branch_name_rejected(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        branch = "main" + "‮" + "evil"
        (git_dir / "HEAD").write_text(f"ref: refs/heads/{branch}\n")
        (git_dir / "refs" / "heads").mkdir(parents=True)
        sha = "f" * 40
        (git_dir / "refs" / "heads" / branch).write_text(sha + "\n")
        located = locate_repository(tmp_path)
        repo = resolve_repository_identity(tmp_path, located)
        assert repo.branch is None
        # The revision itself is still safe (a hex SHA) and is preserved.
        assert repo.revision == sha
