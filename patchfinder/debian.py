import os
import re
import shutil
import tarfile
import urllib.request
from bs4 import BeautifulSoup
DOWNLOAD_DIRECTORY = './cache/'

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
    cve_file = os.path.join(DOWNLOAD_DIRECTORY, 'list')
    fixed_packages = []
    package_paths = []

    #TODO: urlretrieve is most probably deprecated, find something else
    def _download_item(self, url, save_as):
        if os.path.isfile(save_as):
            return
        urllib.request.urlretrieve(url, save_as)

    def find_fixed_packages(self):
        """finds the fixed packages for the current vuln_id

        For a CVE, the cve_file is downloaded from its URL and parsed to look
        for the CVE entry. Upon finding it, the corresponding fixed package name
        and version are extracted.
        """

        self.fixed_packages = []
        self.package_paths = []
        self._download_item(self.cve_list_url, self.cve_file)
        vuln_found = 0
        look_for_cve = re.compile(r'^{vuln_id}'.format(vuln_id=self.vuln_id))
        pkg_ver = re.compile(r'^\t\- (.+?) ([a-zA-Z\d\.\+\-\~:]+?$|[a-zA-Z' \
                             '\d\.\+\-\~:]+? )')
        cve_file = open(self.cve_file)
        try:
            for line in cve_file:
                if vuln_found:
                    if re.match(r'^CVE', line):
                        break
                    matches = pkg_ver.search(line)
                    if matches and len(matches.groups()) is 2:
                        pkg = matches.group(1).strip()
                        ver = re.sub(r'^.+:', r'', matches.group(2).strip())
                        self.fixed_packages.append({'package': pkg,
                                                    'version': ver})
                elif look_for_cve.match(line):
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
                    .format(pkg=package['package'], ver=package['version'])
            snapshot_html = urllib.request.urlopen(snapshot_url)
            soup = BeautifulSoup(snapshot_html, 'html.parser')
            find_pkg = re.compile(r'/({pkg}_{ver}\.(debian\.tar\..+|diff\..+' \
                                  '))$'.format(pkg=package['package'],
                                               ver=package['version']))
            pkg_url = soup.find('a', href=find_pkg)
            assert pkg_url, "Couldn't find package {pkg} {ver} on {url}" \
                    .format(pkg=package['package'],
                            ver=package['version'],
                            url=snapshot_url)
            pkg_url = 'https://snapshot.debian.org/' + pkg_url['href']
            pkg_name = find_pkg.search(pkg_url)
            self._download_item(pkg_url, os.path.join(DOWNLOAD_DIRECTORY,
                                                      pkg_name.group(1)))
            self.package_paths.append({'path': os.path.join(DOWNLOAD_DIRECTORY,
                                                            pkg_name.group(1)),
                                       'source': pkg_url,
                                       'ext_path': \
                                       os.path.join(DOWNLOAD_DIRECTORY,
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
            if tarfile.is_tarfile(package['path']):
                tar = tarfile.open(package['path'])
                try:
                    if 'debian' in tar.getnames():
                        tar.extractall(package['ext_path'])
                finally:
                    tar.close()
                patch_folder = os.path.join(package['ext_path'], \
                                            'debian/patches/')
                try:
                    if os.path.isdir(patch_folder):
                        for f in os.listdir(patch_folder):
                            if f.find(self.vuln_id) is not -1:
                                patches.append({'patch_link': \
                                                os.path.join(patch_folder, f),
                                                'reaching_path': \
                                                package['source']})
                finally:
                    shutil.rmtree(package['ext_path'])
        return patches

    def parse(self, vuln_id):
        self.vuln_id = vuln_id
        self.find_fixed_packages()
        self.retrieve_packages()
        return self.extract_patches()
