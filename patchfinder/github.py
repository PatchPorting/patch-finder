import github

class GithubParser(object):
    """Class for Github as a parser"""

    def search_in_bodies(self, obj, attributes):
        bodies = list(obj.__dict__[attribute]
                      for attribute in attributes)
        for body in bodies:
            if any(string in body for string in self.search_strings):
                return True
        return False

    def _set_search_strings(self, strings):
        self.search_strings.extend(strings)

    def _set_repo(self):
        self.repo = self.github.get_repo(self.repo_name)

    def __init__(self, vuln_id, repo_name):
        self.vuln_id = vuln_id
        self.repo_name = repo_name
        self.github = github.Github()
        self.found_issues = []
        self.found_pulls = []
        self.patches = []
