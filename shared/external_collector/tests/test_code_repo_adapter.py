"""
Unit Tests — Code Repo Adapter
Task 0.3.17 [Seq 41 | QA]

Tests: GitHub GraphQL queries, GitLab REST calls, manifest file extraction.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.adapters.code_repo_adapter import (
    CodeRepoCollector,
    GitHubAdapter,
    GitLabAdapter,
)


class TestGitHubAdapter:
    def test_list_org_repos(self):
        adapter = GitHubAdapter(token="test-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "organization": {
                    "repositories": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [
                            {"name": "repo1", "url": "https://github.com/org/repo1", "isArchived": False, "isPrivate": False, "defaultBranchRef": {"name": "main"}, "pushedAt": "2024-01-15"},
                            {"name": "repo2", "url": "https://github.com/org/repo2", "isArchived": True, "isPrivate": False, "defaultBranchRef": {"name": "main"}, "pushedAt": "2024-01-10"},
                        ],
                    }
                }
            }
        }

        with patch.object(adapter._session, "post", return_value=mock_resp):
            result = adapter.list_org_repos("my-org")
            assert len(result["repos"]) == 2
            assert result["repos"][0]["name"] == "repo1"

    def test_list_org_repos_with_errors(self):
        adapter = GitHubAdapter(token="test-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"errors": [{"message": "Not Found"}]}

        with patch.object(adapter._session, "post", return_value=mock_resp):
            result = adapter.list_org_repos("nonexistent-org")
            assert result["repos"] == []

    def test_fetch_manifest_files(self):
        adapter = GitHubAdapter(token="test-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "repository": {
                    "f0": {"text": '{"name": "my-app", "version": "1.0.0"}'},
                    "f1": None,  # package-lock.json not found
                    "f2": {"text": "flask==2.0.0\nrequests==2.31.0"},
                }
            }
        }

        with patch.object(adapter._session, "post", return_value=mock_resp):
            manifests = adapter.fetch_manifest_files("org", "repo1")
            assert len(manifests) == 2
            assert manifests[0]["filename"] == "package.json"
            assert "my-app" in manifests[0]["content"]
            assert manifests[1]["filename"] == "requirements.txt"

    def test_get_rate_limit(self):
        adapter = GitHubAdapter(token="test-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"rateLimit": {"limit": 5000, "remaining": 4500, "resetAt": "2024-01-15T12:00:00Z"}}
        }

        with patch.object(adapter._session, "post", return_value=mock_resp):
            rate = adapter.get_rate_limit()
            assert rate["remaining"] == 4500


class TestGitLabAdapter:
    def test_list_group_projects(self):
        adapter = GitLabAdapter(token="test-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"id": 1, "path_with_namespace": "group/project1", "default_branch": "main"},
            {"id": 2, "path_with_namespace": "group/project2", "default_branch": "develop"},
        ]

        with patch.object(adapter._session, "get", return_value=mock_resp):
            projects = adapter.list_group_projects("my-group")
            assert len(projects) == 2

    def test_list_group_projects_forbidden(self):
        adapter = GitLabAdapter(token="bad-token")
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch.object(adapter._session, "get", return_value=mock_resp):
            projects = adapter.list_group_projects("private-group")
            assert projects == []

    def test_fetch_manifest_files(self):
        adapter = GitLabAdapter(token="test-token")

        def mock_get(url, **kwargs):
            resp = MagicMock()
            if "package.json" in url:
                resp.status_code = 200
                resp.text = '{"name": "gl-app"}'
            else:
                resp.status_code = 404
            return resp

        with patch.object(adapter._session, "get", side_effect=mock_get):
            manifests = adapter.fetch_manifest_files(1, "main")
            assert len(manifests) == 1
            assert manifests[0]["filename"] == "package.json"


class TestCodeRepoCollector:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.mark.asyncio
    async def test_collect_github_org_no_adapter(self, mock_pool):
        collector = CodeRepoCollector(pool=mock_pool)
        result = await collector.collect_github_org("org")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_collect_gitlab_group_no_adapter(self, mock_pool):
        collector = CodeRepoCollector(pool=mock_pool)
        result = await collector.collect_gitlab_group("group")
        assert "error" in result
