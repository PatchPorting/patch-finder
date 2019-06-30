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
