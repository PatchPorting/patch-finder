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


class Vulnerability(object):
    """Base class for vulnerabilities

    Attributes:
        vuln_id: Self explanatory
        patches: List of patches relevant to the vuln
        packages: Dictionary of packages the vuln affects
                The keys are the provider to which the package name is relevant
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

