import unittest
import unittest.mock as mock
import github
import patchfinder.github as github_parser

class TestGithubParser(unittest.TestCase):
    """Test Class for GithubParser"""


    @classmethod
    def setUpClass(self):
        self.vuln_id = 'CVE-2016-4796'
        self.repo_name = 'uclouvain/openjpeg'
        self.patch_url = 'https://github.com/uclouvain/openjpeg/pull/123.patch'
        self.body_with_vuln = 'This body contains %s' % self.vuln_id
        self.body_without_vuln = 'This body is the body'


    @mock.patch('github.IssueComment.IssueComment',
                spec=github.IssueComment.IssueComment)
    @mock.patch('github.Issue.Issue',
                spec=github.Issue.Issue)
    @mock.patch('patchfinder.github.github.Github',
                spec=github.Github)
    def setUp(self, mock_github, mock_issue, mock_comment):
        self.parser = github_parser.GithubParser()
        self.parser.set_context(self.vuln_id, self.repo_name)
        self.mock_issue = mock_issue
        self.mock_comment = mock_comment


    def test_set_context(self):
        self.assertIsInstance(self.parser.github, github.Github)
        self.assertIn(self.vuln_id, self.parser.search_strings)
        self.parser.github.get_repo.assert_called_with(self.repo_name)


    def test_search_attributes_issue(self):
        attributes = self.parser._search_attributes(self.mock_issue)
        self.assertEqual(attributes, ['title', 'body'])


    def test_search_attributes_comment(self):
        attributes = self.parser._search_attributes(self.mock_comment)
        self.assertEqual(attributes, ['body'])


    def test_search_in_bodies_without_vuln(self):
        self.mock_issue.title = self.body_without_vuln
        self.mock_issue.body = self.body_without_vuln
        self.assertFalse(self.parser.search_in_bodies(self.mock_issue))


    def test_search_in_bodies_with_vuln(self):
        self.mock_issue.title = self.body_without_vuln
        self.mock_issue.body = self.body_with_vuln
        self.assertTrue(self.parser.search_in_bodies(self.mock_issue))


    def test_search_in_issue(self):
        self.mock_issue.title = self.body_without_vuln
        self.mock_issue.body = self.body_without_vuln
        self.mock_comment.body = self.body_with_vuln
        self.mock_issue.get_comments.return_value = [self.mock_comment]

        self.assertTrue(self.parser.search_in_issue(self.mock_issue))
        self.mock_issue.get_comments.assert_called_once()


    @mock.patch('github.PullRequest.PullRequest',
                spec=github.PullRequest.PullRequest)
    def test_find_issues(self, mock_pull):
        self.mock_issue.body = self.body_without_vuln
        self.mock_issue.title = self.body_without_vuln
        self.mock_comment.body = self.body_with_vuln

        self.mock_issue.get_comments.return_value = [self.mock_comment]
        self.mock_issue.pull_request = True

        mock_pull.merged = True
        mock_pull.patch_url = self.patch_url
        self.mock_issue.as_pull_request.return_value = mock_pull

        self.parser.repo.get_issues.return_value = [self.mock_issue]
        self.parser.find_issues()
        self.assertTrue(self.parser.patches)
        self.assertTrue(self.parser.found_issues)
        self.mock_issue.as_pull_request.assert_called_once()
