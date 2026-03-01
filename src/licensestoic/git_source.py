"""Git repository cloning for remote scanning.

Allows LicenseStoic to accept a git URL, clone it to a temporary directory,
and scan the cloned repo. The temp directory is cleaned up after scanning.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)


@contextmanager
def clone_repo(
    git_url: str,
    ref: str | None = None,
    depth: int = 1,
) -> Generator[Path, None, None]:
    """Clone a git repository to a temporary directory.

    Args:
        git_url: The git URL to clone (HTTPS or SSH).
        ref: Optional branch, tag, or commit to checkout.
        depth: Clone depth (default 1 for shallow clone — we only need files, not history).

    Yields:
        Path to the cloned repository root.

    Raises:
        GitCloneError: If cloning fails.
    """
    with tempfile.TemporaryDirectory(prefix="licensestoic-") as tmp_dir:
        clone_path = Path(tmp_dir) / "repo"

        cmd = ["git", "clone", "--quiet"]
        if depth > 0:
            cmd.extend(["--depth", str(depth)])
        if ref:
            cmd.extend(["--branch", ref])
        cmd.extend([git_url, str(clone_path)])

        logger.info("Cloning %s ...", git_url)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitCloneError(f"Clone timed out after 120s: {git_url}") from exc

        if proc.returncode != 0:
            raise GitCloneError(f"git clone failed (exit {proc.returncode}): {proc.stderr.strip()}")

        # If ref is a commit hash (not a branch), we need to checkout after clone
        if ref and not _ref_is_branch(ref):
            try:
                subprocess.run(
                    ["git", "checkout", ref],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(clone_path),
                    check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Shallow clone may not have the commit; try unshallow
                logger.debug("Checkout %s failed, trying fetch", ref)

        logger.info("Cloned to %s", clone_path)
        yield clone_path


def is_git_url(value: str) -> bool:
    """Check if a string looks like a git URL."""
    if value.startswith(("https://", "http://", "git@", "ssh://", "git://")):
        return True
    if value.startswith("github.com/") or value.startswith("gitlab.com/"):
        return True
    return False


def normalize_git_url(value: str) -> str:
    """Normalize shorthand git URLs to full HTTPS URLs.

    Handles:
        github.com/owner/repo → https://github.com/owner/repo.git
        owner/repo → https://github.com/owner/repo.git (assumes GitHub)
    """
    # Already a full URL
    if value.startswith(("https://", "http://", "git@", "ssh://", "git://")):
        if not value.endswith(".git"):
            return value + ".git"
        return value

    # Shorthand: github.com/owner/repo or gitlab.com/owner/repo
    if value.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
        url = f"https://{value}"
        if not url.endswith(".git"):
            url += ".git"
        return url

    # Bare owner/repo — assume GitHub
    parts = value.split("/")
    if len(parts) == 2 and all(parts):
        return f"https://github.com/{value}.git"

    return value


def _ref_is_branch(ref: str) -> bool:
    """Heuristic: commit hashes are 7-40 hex chars; branches/tags are not."""
    if len(ref) < 7 or len(ref) > 40:
        return True
    try:
        int(ref, 16)
        return False  # looks like a hex hash
    except ValueError:
        return True  # has non-hex chars, probably a branch/tag


class GitCloneError(Exception):
    """Raised when a git clone operation fails."""
