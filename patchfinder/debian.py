import logging
import os
import re
import shutil
import tarfile
import urllib.error
import urllib.request
import urllib.parse
import patchfinder.settings as settings
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class DebianParser(object):
    """Class for parsing utilities relevant to Debian

    Attributes:
        cve_list_url: The link to the CVE list used in the Deb Sec Tracker
        cve_file: The path to the file used to save the cve list locally
        fixed_packages: A list of fixed Debian packages w/r/t the input
            vulnerability
    """

    cve_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
            '-tracker/raw/master/data/CVE/list'
    dsa_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
            '-tracker/raw/master/data/DSA/list'
    cve_file = os.path.join(settings.DOWNLOAD_DIRECTORY, 'debian_cve_list')
    pkg_ver = re.compile(r'^[\[\]a-z\s]+\- ([a-zA-Z0-9\+\-\.]+) ([a-zA-Z\d\.' \
                         r'\+\-\~:]+)')
    fixed_packages = []
    package_paths = []


    def parse(self, vuln_id):
        """The parse method for Debian

        The fixed Debian packages w/r/t the given vulnerability are determined
        and retrieved. The debian/patches folder in these packages is checked
        for patches that are relevant to the vulnerability. A list of patches
        found is returned.
        """
        self.vuln_id = vuln_id
        self.find_fixed_packages()
        self.retrieve_packages()
        return self.extract_patches()


    def pkg_ver_in_line(self, line):
        """Extracts package and version from a line

        Args:
            line: String from which the package and version are to be
                extracted

        Returns:
            a dictionary of the package name and its version
        """
        matches = self.pkg_ver.search(line)
        if matches and len(matches.groups()) is 2:
            pkg = matches.group(1).strip()
            ver = re.sub(r'^.+:', r'', matches.group(2).strip())
            return {'package': pkg,
                    'version': ver}
        return None


    def find_fixed_packages(self):
        """finds the fixed packages for the current vuln_id

        For a CVE, the cve_file is downloaded from its URL and parsed to look
        for the CVE entry. Upon finding it, the corresponding fixed package name
        and version are extracted.
        """

        logger.info("Looking for fixed packages...")
        self.fixed_packages = []
        self.package_paths = []
        self._download_item(self.cve_list_url, self.cve_file)
        vuln_found = 0
        look_for_cve = re.compile(r'^{vuln_id}'.format(vuln_id=self.vuln_id))
        cve_file = open(self.cve_file)
        logger.info("Looking for %s in %s", self.vuln_id, self.cve_file)
        try:
            for line in cve_file:
                if vuln_found:
                    if re.match(r'^CVE', line):
                        break
                    pkg_ver = self.pkg_ver_in_line(line)
                    if pkg_ver:
                        logger.info("Found package %s version %s in %s",
                                    pkg_ver['package'],
                                    pkg_ver['version'],
                                    self.cve_file)
                        self.fixed_packages.append(pkg_ver)
                elif look_for_cve.match(line):
                    logger.info("Found %s in %s", self.vuln_id, self.cve_file)
                    vuln_found = 1
        finally:
            cve_file.close()


    def retrieve_packages(self):
        """Downloads the package found by find_fixed_packages

        The Debian packages are downloaded from snapshot.debian.org.
        Since snapshot only has a web interface for access to these packages,
        the corresponding package and version link is extracted and the package
        is downloaded.
        """

        for package in self.fixed_packages:
            snapshot_url = 'https://snapshot.debian.org/package/{pkg}/{ver}/' \
                    .format(pkg=package['package'],
                            ver=package['version'])
            logger.info("Looking for package %s version %s in %s",
                        package['package'],
                        package['version'],
                        snapshot_url)

            try:
                snapshot_html = urllib.request.urlopen(snapshot_url)
            except urllib.error.HTTPError as e:
                raise Exception("Error opening {url}".format(url=snapshot_url))
            logger.info("Crawled %s", snapshot_url)

            soup = BeautifulSoup(snapshot_html, 'html.parser')
            quoted_package = urllib.parse.quote(package['package'])
            quoted_version = urllib.parse.quote(package['version'])
            find_pkg = re.compile(r'/({pkg}_{ver}\.(debian\.tar\..+|diff\..+' \
                                  r'))$'.format(pkg=quoted_package,
                                                ver=quoted_version))
            pkg_url = soup.find('a', href=find_pkg)
            assert pkg_url, "Couldn't find package {pkg} {ver} on {url}" \
                    .format(pkg=package['package'],
                            ver=package['version'],
                            url=snapshot_url)

            pkg_url = urllib.parse.urljoin('https://snapshot.debian.org/',
                                           pkg_url['href'])
            pkg_name = find_pkg.search(pkg_url)
            self._download_item(pkg_url,
                                os.path.join(settings.DOWNLOAD_DIRECTORY,
                                             pkg_name.group(1)))

            self.package_paths.append({'path': \
                                       os.path.join(settings.DOWNLOAD_DIRECTORY,
                                                    pkg_name.group(1)),
                                       'source': pkg_url,
                                       'ext_path': \
                                       os.path.join(settings.DOWNLOAD_DIRECTORY,
                                                    package['package'] + \
                                                    '_' + \
                                                    package['version'])})


   def extract_patches(self):
        """Extract patches from downloaded packages

        If the package is a tar file, all of its contents are extracted.
        The existence of a debian/patches folder is checked in the folder.
        If found, the relevant patches are determined w/r/t the vuln id.
        """

        patches = []
        for package in self.package_paths:
            logger.info("Looking for patches in %s", package['path'])
            if tarfile.is_tarfile(package['path']):
                tar = tarfile.open(package['path'])
                try:
                    if 'debian' in tar.getnames():
                        logger.info("debian folder found in %s", package['path'])
                        tar.extractall(package['ext_path'])
                finally:
                    tar.close()
                logger.info("Contents extracted to %s", package['ext_path'])
                patch_folder = os.path.join(package['ext_path'], \
                                            'debian/patches/')
                try:
                    if not os.path.isdir(patch_folder):
                        continue
                    logger.info("Looking for patches in %s", patch_folder)
                    for f in os.listdir(patch_folder):
                        if f.find(self.vuln_id) is not -1:
                            logger.info("Patch found: %s", f)
                            patches.append({'patch_link': \
                                            os.path.join(patch_folder, f),
                                            'reaching_path': \
                                            package['source']})
                finally:
                    logging.info("Deleting %s", package['ext_path'])
                    shutil.rmtree(package['ext_path'])
        return patches


    #TODO: urlretrieve is most probably deprecated, find something else
    def _download_item(self, url, save_as, overwrite=False):
        """Download an item

        Args:
            url: The url of the item
            save_as: The path to which the item should be saved
            overwrite: optional argument to overwrite existing file with
                same name as save_as. If overwrite is True, the file will
                be downloaded from url and the existing file will be
                overwritten.
        """
        logger.info("Downloading %s as %s...", url, save_as)
        if os.path.isfile(save_as) and not overwrite:
            logger.info("%s exists, not overwriting", save_as)
            return
        parent_dir = os.path.split(save_as)[0]
        if not os.path.isdir(parent_dir):
            os.makedirs(parent_dir)
        urllib.request.urlretrieve(url, save_as)
        logger.info("Downloaded %s...", url)
