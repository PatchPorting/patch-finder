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


    @mock.patch('patchfinder.github.github.Github', spec=github.Github)
    def setUp(self, mock_github):
        self.parser = github_parser.GithubParser()


    def test_set_context(self):
        self.assertIsInstance(self.parser.github, github.Github)
        self.parser.set_context(self.vuln_id, self.repo_name)
        self.assertIn(self.vuln_id, self.parser.search_strings)
        self.parser.github.get_repo.assert_called_with(self.repo_name)


    def test_find_issues(self):
        self.parser.set_context(self.vuln_id, self.repo_name)
        self.parser.find_issues()
        self.parser.repo.get_issues.assert_called_once()


    @mock.patch('github.IssueComment.IssueComment',
                spec=github.IssueComment.IssueComment)
    @mock.patch('github.Issue.Issue',
                spec=github.Issue.Issue)
    def test_search_attributes(self, mock_issue, mock_comment):
        attributes = self.parser._search_attributes(mock_issue)
        self.assertEqual(attributes, ['title', 'body'])

        attributes = self.parser._search_attributes(mock_comment)
        self.assertEqual(attributes, ['body'])


    @mock.patch('github.Issue.Issue', spec=github.Issue.Issue)
    def test_search_in_bodies(self, mock_issue):
        mock_issue.title = 'This issue title is the title'
        mock_issue.body = 'This issue body contains %s' % self.vuln_id
        self.parser.set_context(self.vuln_id, self.repo_name)

        self.assertTrue(self.parser.search_in_bodies(mock_issue))
        mock_issue.body = 'This issue body is now empty'
        self.assertFalse(self.parser.search_in_bodies(mock_issue))
