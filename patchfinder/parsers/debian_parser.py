import logging
import os
import re
import tarfile
import urllib.parse
import patchfinder.settings as settings
import patchfinder.utils as utils

logger = logging.getLogger(__name__)


class DebianParser(object):
    """Class for parsing utilities relevant to Debian

    Attributes:
        cve_list_url: The link to the CVE list used in the Deb Sec Tracker
        cve_file: The path to the file used to save the cve list locally
        fixed_packages: A list of fixed Debian packages w/r/t the input
            vulnerability
    """

    def __init__(self):
        self.cve_list_url = (
            "https://salsa.debian.org/security-tracker-team"
            "/security-tracker/raw/master/data/CVE/list"
        )
        self.dsa_list_url = (
            "https://salsa.debian.org/security-tracker-team"
            "/security-tracker/raw/master/data/DSA/list"
        )
        self.cve_file = os.path.join(
            settings.DOWNLOAD_DIRECTORY, "debian_cve_list"
        )
        self.pkg_ver_line = re.compile(
            r"^[\[\]a-z\s]+\- ([a-zA-Z0-9\+\-\.]+)" r" ([a-zA-Z\d\.\+\-\~:]+)"
        )
        self.file_end_block = re.compile(r"^CVE")
        self.fixed_packages = []
        self.package_paths = []
        self.patches = []

    def parse(self, vuln_id):
        """The parse method for Debian

        The fixed Debian packages w/r/t the given vulnerability are determined
        and retrieved. The debian/patches folder in these packages is checked
        for patches that are relevant to the vulnerability. A list of patches
        found is returned.

        Args:
            vuln_id: Self explanatory

        Returns:
            A list of patches found
        """
        self._clean()
        self.set_context(vuln_id)
        self.find_fixed_packages()
        self.retrieve_packages()
        self.extract_patches()
        return self.patches

    def set_context(self, vuln_id):
        self.vuln_id = vuln_id
        self.file_start_block = re.compile(r"{vuln_id}".format(vuln_id=vuln_id))

    def pkg_ver_in_line(self, matches):
        """Returns a package version dict from a regex object

        Args:
            matches: matches extracted from the CVE file

        Returns:
            a dictionary of the package name and its version
        """
        if len(matches) is 2:
            pkg = matches[0].strip()
            ver = re.sub(r"^.+:", r"", matches[1].strip())
            return {"package": pkg, "version": ver}
        return None

    def find_fixed_packages(self):
        """finds the fixed packages for the current vuln_id

        For a CVE, the cve_file is downloaded from its URL and parsed to look
        for the CVE entry. Upon finding it, the corresponding fixed package name
        and version are extracted.
        """

        logger.info("Looking for fixed packages...")
        utils.download_item(self.cve_list_url, self.cve_file)
        logger.info("Looking for %s in %s", self.vuln_id, self.cve_file)
        pkg_vers = utils.parse_file_by_block(
            self.cve_file,
            self.file_start_block,
            self.file_end_block,
            self.pkg_ver_line,
        )
        for pkg_ver in pkg_vers:
            pkg_ver = self.pkg_ver_in_line(pkg_ver)
            if pkg_ver:
                self.fixed_packages.append(pkg_ver)

    def retrieve_packages(self):
        """Downloads the package found by find_fixed_packages

        The Debian packages are downloaded from snapshot.debian.org.
        Since snapshot only has a web interface for access to these packages,
        the corresponding package and version link is extracted and the package
        is downloaded.
        """

        for package in self.fixed_packages:
            pkg = package["package"]
            ver = package["version"]
            snapshot_url = "https://snapshot.debian.org/package/{pkg}/{ver}/".format(
                pkg=pkg, ver=ver
            )
            find_pkg = re.compile(
                r"/({pkg}_{ver}\.(debian\.tar\..+|diff\..+"
                r"))$".format(
                    pkg=urllib.parse.quote(pkg), ver=urllib.parse.quote(ver)
                )
            )

            pkg_url = utils.parse_web_page(snapshot_url, "a", href=find_pkg)
            if not pkg_url:
                continue
            pkg_url = urllib.parse.urljoin(
                "https://snapshot.debian.org/", pkg_url["href"]
            )
            pkg_name = find_pkg.search(pkg_url).group(1)
            pkg_path = os.path.join(settings.DOWNLOAD_DIRECTORY, pkg_name)
            pkg_ext_path = os.path.join(
                settings.DOWNLOAD_DIRECTORY, pkg + "_" + ver
            )

            utils.download_item(pkg_url, pkg_path)
            self.package_paths.append(
                {"path": pkg_path, "source": pkg_url, "ext_path": pkg_ext_path}
            )

    def extract_patches(self):
        """Extract patches from downloaded packages

        Relevant patches are searched for in the tarball.
        """

        for package in self.package_paths:
            pkg_path = package["path"]
            pkg_source = package["source"]
            logger.info("Looking for patches in %s", pkg_path)
            if tarfile.is_tarfile(pkg_path):
                tar = tarfile.open(pkg_path)
                for member in tar.getmembers():
                    if (
                        member.name.endswith(".patch")
                        and member.name.find(self.vuln_id) is not -1
                    ):
                        self.patches.append(
                            {
                                "patch_link": member.name,
                                "reaching_path": pkg_source,
                            }
                        )

    def _clean(self):
        self.fixed_packages = []
        self.package_paths = []
        self.patches = []
