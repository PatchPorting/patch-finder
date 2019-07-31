"""Provides parsing functionaility for Github repositories.

This module uses the Github API to look for commits specific to a vulnerability
in a repository.

Attributes:
    logger: Module level logger.
"""
import argparse
import logging
import github

logger = logging.getLogger(__name__)


class GithubParser(object):
    """Class for Github as a parser

    This class will be used for parsing an upstream repository
    located at Github.

    Attributes:
        github: The main class of the Github Client
        repo: The github Repository object
        search_strings: A list of strings to be searched for in the repo
            entities
        found_issues: A list of issues relevant to context
        patches: A list of patches found relevant to context
    """

    def __init__(self):
        self.github = github.Github()
        self.search_strings = []
        self.found_issues = []
        self.patches = []

    def parse(self, vuln_id, repo_name):
        """The parse method

        The context of the searching is first set, and the repo's entities
        are then searched for patches.

        Args:
            vuln_id: The vulnerability ID to for which patches are to be
                found.
            repo_name: The owner-name, repo-name pair designating the
                repository

        Returns:
            A list of patches found
        """
        self._clean()
        self.set_context(vuln_id, repo_name)
        self.find_issues()
        return self.patches

    def set_context(self, vuln_id, repo_name):
        """Set the context of the patch finding

        Parameters relevant to the patch finding for Github are taken
        and set accordingly.

        Args:
            vuln_id: The vulnerability ID to for which patches are to be
                found.
            repo_name: The owner-name, repo-name pair designating the
                repository
        """
        self.vuln_id = vuln_id
        self._add_to_search_strings(vuln_id)
        self._set_repo(repo_name)

    def query_strings(self):
        for string in self.search_strings:
            yield "{string}+repo:{repo_name}".format(
                string=string, repo_name=self.repo.full_name
            )

    def find_issues(self):
        """Find issues (and patches) relevant to the parser's context

        The repository's issues are parsed one by one to look for
        issues relevant to the context. If an issue is in context of the
        parser, it is added to relevant data structures
        """
        found_issues = []
        queries = self.query_strings()
        logger.info("Looking for issues in %s", self.repo.full_name)
        for query in queries:
            logger.info("Querying Github with query %s", query)
            issues = self.github.search_issues(query)
            for issue in issues:
                logger.info("Found issue #%s", str(issue.number))
                found_issues.append(issue)
        for issue in found_issues:
            self._add_issue(issue)

    def patch_from_issue(self, issue):
        if issue.pull_request:
            pull = issue.as_pull_request()
            if pull.merged:
                return pull.patch_url
        return None

    def _add_issue(self, issue):
        """Extract patches from an issue and append it to other data structures

        If the issue has a corresponding pull request, the pull's patch url is
        appended to the found patches list if the pull has been merged.
        The issue ID is taken and formatted for easily recognizing it
        in other repository entities. This includes shifting a hash (#)
        symbol to the start of the issue ID. The formatted issue ID is
        appended to the found issues list and, if it is not present in it, the
        search strings list as well.

        Args:
            issues: A github Issue object
        """
        issue_id = "#" + str(issue.number)
        if issue_id not in self.found_issues:
            logger.info("Adding issue %s", issue_id)
            self.found_issues.append(issue_id)
        patch_link = self.patch_from_issue(issue)
        if patch_link:
            logger.info(
                "Patch found from corresponding pull %s: %s",
                issue_id,
                patch_link,
            )
            self._add_to_patches(patch_link)
        if issue_id not in self.search_strings:
            self._add_to_search_strings(issue_id)

    def _add_to_patches(self, patch_link):
        """Append a patch url to the list of patches found

        Args:
            patch_link: The patch URL to append
        """
        if patch_link not in self.patches:
            self.patches.append(patch_link)

    def _clean(self):
        self.found_issues = []
        self.patches = []

    def _add_to_search_strings(self, *strings):
        """Append one or more strings to the search strings list

        Args:
            strings: One or more strings
        """
        self.search_strings.extend(strings)

    def _set_repo(self, repo_name):
        """Set the github.Repository.Repository object

        Args:
            repo_name: The owner-name, repo-name pair designating the
                repository. This should be in the format:
                <owner_name>/<repo_name>
        """
        self.repo = self.github.get_repo(repo_name)


if __name__ == "__main__":
    logging.getLogger("github").setLevel(logging.CRITICAL)
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vuln_id", help="The vulnerability ID to find patches for"
    )
    parser.add_argument(
        "repo_name",
        help="The name of the Github repository in the form"
             "<owner-name>/<repo-name>",
    )
    args = parser.parse_args()
    github_parser = GithubParser()
    github_parser.parse(args.vuln_id, args.repo_name)
