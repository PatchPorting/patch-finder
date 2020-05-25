"""Tests for Github Parser."""
#TODO: Rewrite most of these tests.
import unittest
import unittest.mock as mock

import github

from patchfinder.parsers.github_parser import GithubParser


class TestGithubParser(unittest.TestCase):
    """Test Class for GithubParser"""

    @classmethod
    def setUpClass(cls):
        cls.vuln_id = "CVE-2016-4796"
        cls.repo_name = "uclouvain/openjpeg"
        cls.patch_url = "https://github.com/uclouvain/openjpeg/pull/123.patch"

    @mock.patch("github.Issue.Issue", spec=github.Issue.Issue)
    @mock.patch(
        "patchfinder.parsers.github_parser.github.Github", spec=github.Github
    )
    def setUp(self, mock_github, mock_issue):
        self.parser = GithubParser()
        self.parser.set_context(self.vuln_id, self.repo_name)
        self.parser.repo.full_name = self.repo_name
        self.mock_issue = mock_issue
        self.mock_issue.number = 123

    def test_set_context(self):
        self.assertIsInstance(self.parser.github, github.Github)
        self.assertIn(self.vuln_id, self.parser.search_strings)
        self.parser.github.get_repo.assert_called_with(self.repo_name)

    @mock.patch(
        "github.PullRequest.PullRequest", spec=github.PullRequest.PullRequest
    )
    def test_patch_from_issue_with_merged_pull(self, mock_pull):
        mock_pull.merged = True
        mock_pull.patch_url = self.patch_url
        self.mock_issue.pull_request = True
        self.mock_issue.as_pull_request.return_value = mock_pull
        self.assertEqual(
            self.parser.patch_from_issue(self.mock_issue), self.patch_url
        )

    @mock.patch(
        "github.PullRequest.PullRequest", spec=github.PullRequest.PullRequest
    )
    def test_patch_from_issue_with_unmerged_pull(self, mock_pull):
        mock_pull.merged = False
        self.mock_issue.pull_request = True
        self.mock_issue.as_pull_request.return_value = mock_pull
        self.assertFalse(self.parser.patch_from_issue(self.mock_issue))

    def test_patch_from_issue_with_no_pull(self):
        self.mock_issue.pull_request = False
        self.assertFalse(self.parser.patch_from_issue(self.mock_issue))
        self.mock_issue.as_pull_request.assert_not_called()

    @mock.patch(
        "github.PullRequest.PullRequest", spec=github.PullRequest.PullRequest
    )
    def test_find_issues(self, mock_pull):
        self.mock_issue.pull_request = True
        mock_pull.merged = True
        mock_pull.patch_url = self.patch_url

        self.mock_issue.as_pull_request.return_value = mock_pull
        self.parser.github.search_issues.return_value = [self.mock_issue]

        self.parser.find_issues()
        self.assertTrue(self.parser.patches)
        self.assertTrue(self.parser.found_issues)
