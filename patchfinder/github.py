import github

class GithubParser(object):
    """Class for Github as a parser"""

    def search_in_bodies(self, obj, *attributes):
        bodies = list(obj.__dict__[attribute]
                      for attribute in attributes)
        for body in bodies:
            if any(string in body for string in self.search_strings):
                return True
        return False

    def _add_to_search_strings(self, *strings):
        self.search_strings.extend(strings)

    def _set_repo(self, repo_name):
        self.repo = self.github.get_repo(repo_name)

    def append_issues(self, issues):
        for issue in issues:
            issue_id = '#' + str(issue.id)
            self.found_issues.append(issue_id)
            if issue_id not in self.search_strings:
                self.add_to_search_strings(issue_id)

    def find_issues(self):
        issues = self.repo.get_issues()
        found_issues = []
        for issue in issues:
            comments = issue.get_comments()
            if self.search_in_bodies(issue, 'title', 'body'):
                found_issues.append(issue)
            else:
                for comment in comments:
                    if self.search_in_bodies(comment, 'body'):
                        found_issues.append(issue)
                        break
        self.append_issues(found_issues)

    def set_context(self, vuln_id, repo_name):
        self._add_to_search_strings(vuln_id)
        self._set_repo(repo_name)

    def __init__(self):
        self.github = github.Github()
        self.search_strings = []
        self.found_issues = []
        self.found_pulls = []
        self.patches = []
