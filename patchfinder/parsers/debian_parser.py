"""Provides parsing functionality for Debian sites and packages.

This module determines fixed packages relevant to a vulnerability and extracts
relevant patches from those packages.

Attributes:
    logger: Module level logger.
"""
import argparse
import logging
import os
import re
import tarfile
import urllib.parse
import urllib.request

import patchfinder.utils as utils
from patchfinder.settings import PatchfinderSettings

logger = logging.getLogger(__name__)


class DebianParser:
    """Class for parsing utilities relevant to Debian

    Attributes:
        _fixed_packages (list[dict{str: str}]): A dict of fixed Debian packages
            w/r/t the input vulnerability.
        _package_paths (list[dict{str: str}]): A dict of paths to downloaded
            package tarballs.
        _patches (list[dict{str: str}]): A dict of scraped patches.
    """

    def __init__(self, **kwargs):
        settings = kwargs.get("settings")
        if not settings:
            settings = PatchfinderSettings()
        self.settings = settings
        self._fixed_packages = []
        self._package_paths = []
        self._patches = []

    def parse(self, vuln_id):
        """The parse method for Debian.

        The fixed Debian packages w/r/t the given vulnerability are determined
        and retrieved. The debian/patches folder in these packages is checked
        for patches that are relevant to the vulnerability. A list of patches
        found is returned.

        Args:
            vuln_id (str): The vulnerability ID to set the context of the parser.

        Returns:
            list[dict{str: str}]: A list of patches found.
        """
        self._clean()
        self.set_context(vuln_id)
        self._find_fixed_packages()
        self._retrieve_packages()
        self._extract_patches()
        return self._patches

    def set_context(self, vuln_id):
        self.vuln_id = vuln_id

    def _find_fixed_packages(self):
        """Finds the fixed packages for the instance's vulnerability ID.

        For a CVE, the corresponding fixed package names and their versions are
        scraped from the Debian Security Tracker.
        """
        pkg_vers = []
        logger.info("Looking for fixed packages...")
        url = "https://security-tracker.debian.org/tracker/{vuln_id}".format(
            vuln_id=self.vuln_id
        )
        pkg_vers = utils.parse_web_page(url)

        # Group package names and versions into pairwise tuples
        pkg_vers = list(zip(pkg_vers[::2], pkg_vers[1::2]))
        for pkg_ver in pkg_vers:
            if not re.match(r"^\d", pkg_ver[1]):
                continue
            self._fixed_packages.append(
                {"package": pkg_ver[0], "version": pkg_ver[1]}
            )

    def _retrieve_packages(self):
        """Downloads the fixed packages.

        The Debian packages are downloaded from snapshot.debian.org.
        Since snapshot only has a web interface for access to these packages,
        the corresponding package and version link is extracted and the package
        is downloaded. This package is a tarball.
        """

        for package in self._fixed_packages:
            pkg = package["package"]
            ver = package["version"]
            snapshot_url = "https://snapshot.debian.org/package/{pkg}/{ver}/".format(
                pkg=pkg, ver=ver
            )
            find_pkg = "//a/@href[contains(., '{pkg}_{ver}.debian')]".format(
                pkg=urllib.parse.quote(pkg), ver=urllib.parse.quote(ver)
            )
            pkg_url = utils.parse_web_page(snapshot_url, xpaths=[find_pkg])
            if not pkg_url:
                continue
            pkg_url = urllib.parse.urljoin(
                "https://snapshot.debian.org/", pkg_url.pop()
            )
            pkg_path = os.path.join(
                self.settings["DOWNLOAD_DIRECTORY"], pkg_url.split("/")[-1]
            )
            utils.download_item(pkg_url, pkg_path)
            self._package_paths.append({"path": pkg_path, "source": pkg_url})

    def _extract_patches(self):
        """Extract patches from downloaded packages.

        Members of the tarballs that are patches and are relevant to the
        vulnerability are extracted.
        """
        for package in self._package_paths:
            pkg_path = package["path"]
            pkg_source = package["source"]
            logger.info("Looking for patches in %s", pkg_path)
            if tarfile.is_tarfile(pkg_path):
                tar = tarfile.open(pkg_path)
                for member in tar.getmembers():
                    if (
                            member.name.startswith("debian/patches")
                            and member.name.find(self.vuln_id) is not -1
                    ):
                        logger.info(
                            "Found patch: %s in %s", member.name, pkg_source
                        )
                        self._patches.append(
                            {
                                "patch_link": member.name,
                                "reaching_path": pkg_source,
                            }
                        )

    def _clean(self):
        self._fixed_packages = []
        self._package_paths = []
        self._patches = []


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vuln_id", help="The vulnerability ID to find patches for"
    )
    args = parser.parse_args()
    debian_parser = DebianParser()
    debian_parser.parse(args.vuln_id)
