import logging
import github

logger = logging.getLogger(__name__)

class GithubParser(object):
    """Class for Github as a parser"""


    def __init__(self):
        self.github = github.Github()
        self.search_strings = []
        self.found_issues = []
        self.patches = []


    def parse(self, vuln_id, repo_name):
        self.set_context()
        self.find_issues()
        return self.patches


    def set_context(self, vuln_id, repo_name):
        self._add_to_search_strings(vuln_id)
        self._set_repo(repo_name)


    def find_issues(self):
        issues = self.repo.get_issues()
        found_issues = []
        for issue in issues:
            comments = issue.get_comments()
            issue_objs = list(issue).extend(list(comments))
            for issue_obj in issue_objs:
                if self.search_in_bodies(issue_obj):
                    #TODO: PR is pulled twice, find better soln. for this
                    if issue.pull_request:
                        pull = issue.as_pull_request()
                        if pull.merged:
                            self.add_to_patches(pull.patch_url)
                    found_issues.append(issue)
                    break
        self.append_issues(found_issues)


    def append_issues(self, issues):
        for issue in issues:
            issue_id = '#' + str(issue.id)
            self.found_issues.append(issue_id)
            if issue_id not in self.search_strings:
                self._add_to_search_strings(issue_id)


    def add_to_patches(self, patch_url):
        if patch_url not in self.patches:
            self.patches.append(patch_url)


    def search_in_bodies(self, obj):
        attributes = self._search_attributes(obj)
        bodies = list(obj.__dict__[attribute]
                      for attribute in attributes)
        for body in bodies:
            if any(string in body for string in self.search_strings):
                return True
        return False


    def _search_attributes(self, github_obj):
        if (isinstance(github_obj,
                       type(github.Issue.Issue))
            or isinstance(github_obj,
                          type(github.PullRequest.PullRequest))):
            return ['title', 'body']
        elif (isinstance(github_obj,
                         type(github.IssueComment.IssueComment))
              or isinstance(github_obj,
                        type(github.PullRequestComment.PullRequestComment))):
            return ['body']
        return []


    def _add_to_search_strings(self, *strings):
        self.search_strings.extend(strings)


    def _set_repo(self, repo_name):
        self.repo = self.github.get_repo(repo_name)
