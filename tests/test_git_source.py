"""Tests for git URL handling and normalization."""

from licensestoic.git_source import is_git_url, normalize_git_url


class TestIsGitUrl:
    def test_https_url(self) -> None:
        assert is_git_url("https://github.com/owner/repo.git") is True

    def test_ssh_url(self) -> None:
        assert is_git_url("git@github.com:owner/repo.git") is True

    def test_github_shorthand(self) -> None:
        assert is_git_url("github.com/owner/repo") is True

    def test_local_path_not_git_url(self) -> None:
        assert is_git_url("/some/local/path") is False
        assert is_git_url(".") is False

    def test_bare_owner_repo_not_detected(self) -> None:
        # owner/repo is handled by _looks_like_repo_shorthand, not is_git_url
        assert is_git_url("owner/repo") is False


class TestNormalizeGitUrl:
    def test_full_https_unchanged(self) -> None:
        url = "https://github.com/owner/repo.git"
        assert normalize_git_url(url) == url

    def test_https_without_git_suffix(self) -> None:
        assert normalize_git_url("https://github.com/owner/repo") == (
            "https://github.com/owner/repo.git"
        )

    def test_github_shorthand(self) -> None:
        assert normalize_git_url("github.com/owner/repo") == ("https://github.com/owner/repo.git")

    def test_bare_owner_repo_assumes_github(self) -> None:
        assert normalize_git_url("owner/repo") == "https://github.com/owner/repo.git"

    def test_ssh_url_unchanged(self) -> None:
        url = "git@github.com:owner/repo.git"
        assert normalize_git_url(url) == url

    def test_gitlab_shorthand(self) -> None:
        assert normalize_git_url("gitlab.com/group/project") == (
            "https://gitlab.com/group/project.git"
        )
