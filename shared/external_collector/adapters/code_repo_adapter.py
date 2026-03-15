"""
Code Repository Adapter — Task 0.3.5 [Seq 29 | BD]

Fetches repository metadata and manifest files from GitHub (GraphQL) and
GitLab (REST) so that engine_supplychain can extract and scan dependencies.

Input:  {git_provider, org_or_account_id}
Output: Rows in package_metadata with {repo_name, repo_url, manifest_file, file_content}

Dependencies:
  - Task 0.3.2 (credential_manager for GitHub/GitLab tokens)
  - Task 0.3.1 (package_metadata table)
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.code_repo")

# Manifest files to scan for in each repository
MANIFEST_FILES = [
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
]

# GitHub GraphQL endpoint
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# GitLab default base URL (self-hosted can override)
GITLAB_BASE_URL = "https://gitlab.com"


class GitHubAdapter:
    """Fetches repos and manifest files via GitHub GraphQL API.

    Rate limit: 5000 points/hour (GraphQL).

    Args:
        token: GitHub personal access token or app token.
    """

    def __init__(self, token: str) -> None:
        self._token = token
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"bearer {token}",
            "Content-Type": "application/json",
        })

    def list_org_repos(
        self, org: str, first: int = 100, after: Optional[str] = None
    ) -> Dict[str, Any]:
        """List repositories in an organization via GraphQL.

        Args:
            org: GitHub organization login.
            first: Number of repos per page (max 100).
            after: Cursor for pagination.

        Returns:
            Dict with repos list and pageInfo.
        """
        query = """
        query($org: String!, $first: Int!, $after: String) {
          organization(login: $org) {
            repositories(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
              pageInfo { hasNextPage, endCursor }
              nodes {
                name
                url
                isArchived
                isPrivate
                defaultBranchRef { name }
                pushedAt
              }
            }
          }
        }
        """
        variables = {"org": org, "first": first}
        if after:
            variables["after"] = after

        resp = self._session.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query, "variables": variables},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            logger.error("GitHub GraphQL errors: %s", data["errors"])
            return {"repos": [], "page_info": {"hasNextPage": False}}

        org_data = data.get("data", {}).get("organization", {})
        repos_data = org_data.get("repositories", {})
        return {
            "repos": repos_data.get("nodes", []),
            "page_info": repos_data.get("pageInfo", {}),
        }

    def fetch_manifest_files(
        self, owner: str, repo: str, branch: str = "main"
    ) -> List[Dict[str, str]]:
        """Fetch manifest files from a repository.

        Args:
            owner: Repository owner (org or user).
            repo: Repository name.
            branch: Branch to read from.

        Returns:
            List of {filename, content} dicts for found manifests.
        """
        # Build a single GraphQL query that checks all manifest files at once
        file_fragments = []
        for i, filename in enumerate(MANIFEST_FILES):
            safe_alias = f"f{i}"
            file_fragments.append(
                f'{safe_alias}: object(expression: "{branch}:{filename}") {{ ... on Blob {{ text }} }}'
            )

        query = "query($owner: String!, $repo: String!) {\n"
        query += "  repository(owner: $owner, name: $repo) {\n"
        query += "\n".join(f"    {frag}" for frag in file_fragments)
        query += "\n  }\n}"

        resp = self._session.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query, "variables": {"owner": owner, "repo": repo}},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            logger.warning("GitHub manifest fetch errors for %s/%s: %s", owner, repo, data["errors"])

        manifests: List[Dict[str, str]] = []
        repo_data = data.get("data", {}).get("repository", {})
        for i, filename in enumerate(MANIFEST_FILES):
            alias = f"f{i}"
            blob = repo_data.get(alias)
            if blob and blob.get("text"):
                manifests.append({"filename": filename, "content": blob["text"]})

        return manifests

    def get_rate_limit(self) -> Dict[str, Any]:
        """Check current GraphQL rate limit status."""
        query = "{ rateLimit { limit remaining resetAt } }"
        resp = self._session.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("rateLimit", {})


class GitLabAdapter:
    """Fetches projects and manifest files via GitLab REST API.

    Rate limit: 600/minute.

    Args:
        token: GitLab personal access token.
        base_url: GitLab instance base URL.
    """

    def __init__(self, token: str, base_url: str = GITLAB_BASE_URL) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"PRIVATE-TOKEN": token})

    def list_group_projects(
        self, group_id: str, page: int = 1, per_page: int = 100
    ) -> List[Dict[str, Any]]:
        """List projects in a GitLab group.

        Args:
            group_id: GitLab group ID or path (URL-encoded).
            page: Page number.
            per_page: Results per page.

        Returns:
            List of project dicts.
        """
        url = f"{self._base_url}/api/v4/groups/{group_id}/projects"
        resp = self._session.get(
            url,
            params={"page": page, "per_page": per_page, "order_by": "last_activity_at"},
            timeout=30,
        )

        if resp.status_code == 403:
            logger.warning("GitLab 403 for group %s — skipping (private)", group_id)
            return []

        resp.raise_for_status()
        return resp.json()

    def fetch_manifest_files(
        self, project_id: int, branch: str = "main"
    ) -> List[Dict[str, str]]:
        """Fetch manifest files from a GitLab project.

        Args:
            project_id: GitLab project numeric ID.
            branch: Branch to read from.

        Returns:
            List of {filename, content} dicts.
        """
        manifests: List[Dict[str, str]] = []

        for filename in MANIFEST_FILES:
            url = (
                f"{self._base_url}/api/v4/projects/{project_id}"
                f"/repository/files/{requests.utils.quote(filename, safe='')}/raw"
            )
            resp = self._session.get(
                url,
                params={"ref": branch},
                timeout=15,
            )

            if resp.status_code == 200:
                manifests.append({"filename": filename, "content": resp.text})
            elif resp.status_code == 404:
                continue  # File not in repo
            elif resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "60"))
                logger.warning("GitLab rate limited, sleeping %ds", retry_after)
                time.sleep(retry_after)
            else:
                logger.warning(
                    "GitLab file fetch %s from project %d: HTTP %d",
                    filename, project_id, resp.status_code,
                )

        return manifests


class CodeRepoCollector:
    """Orchestrates fetching repos and manifests, storing results in DB.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
        github_adapter: Optional GitHubAdapter instance.
        gitlab_adapter: Optional GitLabAdapter instance.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        github_adapter: Optional[GitHubAdapter] = None,
        gitlab_adapter: Optional[GitLabAdapter] = None,
    ) -> None:
        self._pool = pool
        self._github = github_adapter
        self._gitlab = gitlab_adapter

    async def collect_github_org(self, org: str) -> Dict[str, Any]:
        """Collect all repos and manifests from a GitHub organization.

        Args:
            org: GitHub organization login.

        Returns:
            Dict with repos_found, manifests_stored, errors.
        """
        if not self._github:
            return {"error": "GitHub adapter not configured"}

        repos_found = 0
        manifests_stored = 0
        errors = 0
        after = None

        while True:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._github.list_org_repos, org, 100, after
            )

            repos = result.get("repos", [])
            repos_found += len(repos)

            for repo in repos:
                if repo.get("isArchived"):
                    continue

                repo_name = repo["name"]
                default_branch = (repo.get("defaultBranchRef") or {}).get("name", "main")

                try:
                    manifests = await asyncio.get_event_loop().run_in_executor(
                        None,
                        self._github.fetch_manifest_files,
                        org,
                        repo_name,
                        default_branch,
                    )

                    for manifest in manifests:
                        await self._store_manifest(
                            source="github",
                            repo_name=f"{org}/{repo_name}",
                            repo_url=repo.get("url", ""),
                            filename=manifest["filename"],
                            content=manifest["content"],
                        )
                        manifests_stored += 1

                except Exception as exc:
                    logger.error("Error fetching manifests for %s/%s: %s", org, repo_name, exc)
                    errors += 1

            page_info = result.get("page_info", {})
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")

        logger.info(
            "GitHub org %s: %d repos, %d manifests stored, %d errors",
            org, repos_found, manifests_stored, errors,
        )
        return {
            "repos_found": repos_found,
            "manifests_stored": manifests_stored,
            "errors": errors,
        }

    async def collect_gitlab_group(self, group_id: str) -> Dict[str, Any]:
        """Collect all projects and manifests from a GitLab group.

        Args:
            group_id: GitLab group ID or path.

        Returns:
            Dict with repos_found, manifests_stored, errors.
        """
        if not self._gitlab:
            return {"error": "GitLab adapter not configured"}

        repos_found = 0
        manifests_stored = 0
        errors = 0
        page = 1

        while True:
            projects = await asyncio.get_event_loop().run_in_executor(
                None, self._gitlab.list_group_projects, group_id, page, 100
            )

            if not projects:
                break

            repos_found += len(projects)

            for project in projects:
                project_id = project["id"]
                default_branch = project.get("default_branch", "main")

                try:
                    manifests = await asyncio.get_event_loop().run_in_executor(
                        None,
                        self._gitlab.fetch_manifest_files,
                        project_id,
                        default_branch,
                    )

                    for manifest in manifests:
                        await self._store_manifest(
                            source="gitlab",
                            repo_name=project.get("path_with_namespace", ""),
                            repo_url=project.get("web_url", ""),
                            filename=manifest["filename"],
                            content=manifest["content"],
                        )
                        manifests_stored += 1

                except Exception as exc:
                    logger.error(
                        "Error fetching manifests for project %d: %s",
                        project_id, exc,
                    )
                    errors += 1

            if len(projects) < 100:
                break
            page += 1

        logger.info(
            "GitLab group %s: %d projects, %d manifests stored, %d errors",
            group_id, repos_found, manifests_stored, errors,
        )
        return {
            "repos_found": repos_found,
            "manifests_stored": manifests_stored,
            "errors": errors,
        }

    async def _store_manifest(
        self,
        source: str,
        repo_name: str,
        repo_url: str,
        filename: str,
        content: str,
    ) -> None:
        """Store a manifest file in package_metadata table."""
        sql = """
            INSERT INTO package_metadata (
                package_name, registry, version, metadata, refreshed_at
            ) VALUES ($1, $2, $3, $4::jsonb, NOW())
            ON CONFLICT (package_name, registry, version)
            DO UPDATE SET
                metadata = EXCLUDED.metadata,
                refreshed_at = NOW()
        """
        metadata = json.dumps({
            "source": source,
            "repo_name": repo_name,
            "repo_url": repo_url,
            "manifest_file": filename,
            "file_content": content,
        })
        async with self._pool.acquire() as conn:
            await conn.execute(
                sql,
                f"{repo_name}/{filename}",  # package_name
                source,                       # registry (github/gitlab)
                "HEAD",                        # version (latest)
                metadata,
            )
