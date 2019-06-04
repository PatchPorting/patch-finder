from collections import deque
import re
import patchfinder.entrypoint as entrypoint

class Patch(object):
    """Base class for Patch

    Attributes:
        patch_link: Self explanatory
        source_version: The source version the patch pertains to
        reaching_path: The path taken by the finder to find the patch
    """

    def __init__(self, context, patch_link, source_version=None):
        self.patch_link = patch_link
        self.source_version = source_version
        self.reaching_path = context.current_path


class Context(object):
    """Base Class for the runtime context of the patch finder

    Attributes:
        vuln: The current Vulnerability object
        current_path: A linked list of the current path the finder is on
        recursion_limit: The depth of recursion performed while crawling
        visited_urls: A list of visited pages
    """

    def __init__(self, vuln, recursion_limit=0):
        self.vuln = vuln
        self.current_path = deque([])
        self.recursion_limit = recursion_limit if (recursion_limit > 0) else 0
        self.visited_urls = []

    def add_to_path(self, url):
        self.current_path.append(url)

    def pop_path_left(self):
        if not self.current_path:
            raise IndexError('finder in root of path, can\'t pop from path')
        self.current_path.popleft()

    def pop_path_right(self):
        if not self.current_path:
            raise IndexError('finder in root of path, can\'t pop from path')
        self.current_path.pop()

    def add_to_visited_urls(self, url):
        self.visited_urls.append(url)

    def check_if_visited(self, url):
        if url in self.visited_urls:
            return True
        return False


class Vulnerability(object):
    """Base class for vulnerabilities

    Attributes:
        vuln_id: Self explanatory
        patches: List of patches relevant to the vuln
        packages: List of packages the vuln affects
    """

    def __init__(self, vuln_id, packages=None):
        self.vuln_id = vuln_id
        self.patches = []
        self.packages = packages

    def add_patch(self, context, patch_link, source_version=None):
        patch = Patch(context, patch_link, source_version)
        self.patches.append(patch)


class CVE(Vulnerability):
    """Subclass for CVE"""

    def __init__(self, vuln_id, packages=None):
        super(CVE, self).__init__(vuln_id, packages)
        self.entrypoints = [entrypoint.NVD(vuln_id),
                            entrypoint.MITRE(vuln_id)]


def create_vuln(vuln_id, packages=None):
    if re.match(r'^CVE\-\d+\-\d+$', vuln_id, re.I):
        return CVE(vuln_id, packages)
    return None


def create_context(vuln_id, packages=None):
    vuln = create_vuln(vuln_id, packages)
    if vuln:
        context = Context(vuln)
        return context
    return None

