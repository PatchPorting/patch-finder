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
        self._add_to_search_strings(vuln_id)
        self._set_repo(repo_name)


    def search_in_issue(self, issue):
        """Determine if an issue is in context of the parser

        The issue's title and body, and its comments' bodies are searched
        for any of the search strings.

        Args:
            issue: A github issue object

        Returns:
            True if the issue has any of the search strings, False otherwise
        """
        if self.search_in_bodies(issue):
            return True
        comments = issue.get_comments()
        for comment in comments:
            if self.search_in_bodies(comment):
                return True
        return False


    def find_issues(self):
        """Find issues (and patches) relevant to the parser's context

        The repository's issues are parsed one by one to look for
        issues relevant to the context. If an issue is in context of the
        parser, the existence of a corresponding pull request is checked.
        If found, the pull is taken as a patch and appended to the found
        patches list.
        """
        issues = self.repo.get_issues()
        found_issues = []
        for issue in issues:
            if self.search_in_issue(issue):
                #TODO: PR is pulled twice, find better soln. for this
                if issue.pull_request:
                    pull = issue.as_pull_request()
                    if pull.merged:
                        self.add_to_patches(pull.patch_url)
            found_issues.append(issue)
        self.append_issues(found_issues)


    def append_issues(self, issues):
        """Format the issues and append them in the found issues list

        The issue IDs are taken and formatted for easily recognizing them
        in other repository entities. This includes shifting a hash (#)
        symbol to the start of the issue ID. The formatted issue ID is
        appended to the found issues list and, if it is not present in it, the
        search strings list as well.

        Args:
            issues: A list of github issue objects.
        """
        for issue in issues:
            issue_id = '#' + str(issue.id)
            self.found_issues.append(issue_id)
            if issue_id not in self.search_strings:
                self._add_to_search_strings(issue_id)


    def add_to_patches(self, patch_url):
        """Append a patch url to the list of patches found

        Args:
            patch_url: The patch URL to append
        """
        if patch_url not in self.patches:
            self.patches.append(patch_url)


    #NOTE: This may belong in the miscellaneous utils library
    def search_in_bodies(self, github_obj):
        """Search in the text bodies of the object for the search strings

        The object's relevant text body attributes are searched for any
        of the strings in the list of search strings

        Args:
            github_obj: A github object

        Returns:
            True if any of the search strings are found, False otherwise
        """
        attributes = self._search_attributes(github_obj)
        bodies = list(github_obj.__dict__[attribute]
                      for attribute in attributes)
        for body in bodies:
            if any(string in body for string in self.search_strings):
                return True
        return False


    def _search_attributes(self, github_obj):
        """Return a list of text body attributes of an object for searching.

        Args:
            github_obj: A github object

        Returns:
            A list of text body attributes that the parser should search in.
                If github_obj is not identified, an empty list is returned.
        """
        if (isinstance(github_obj,
                       github.Issue.Issue)):
            return ['title', 'body']
        elif (isinstance(github_obj,
                         github.IssueComment.IssueComment)):
            return ['body']
        return []


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
