import os
import tarfile
import shutil
import unittest
import unittest.mock as mock
import urllib.parse
import patchfinder.settings as settings
from patchfinder.parsers import DebianParser


class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def setUp(self):
        self.parser = DebianParser()
        self.parser.cve_file = "./tests/mocks/mock_debian_cve_list"

    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_fixed_packages(self, mock_download_method):
        vuln_id = "CVE-2019-12795"
        self.parser.set_context(vuln_id)
        self.parser.find_fixed_packages()
        mock_download_method.assert_called_with(
            self.parser.cve_list_url, self.parser.cve_file
        )
        self.assertTrue(
            {"package": "gvfs", "version": "1.38.1-5"}
            in self.parser.fixed_packages
        )
        self.assertEqual(len(self.parser.fixed_packages), 1)

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_retrieve_packages(self, mock_download_method, mock_page_parse):
        pkg = "openjpeg2"
        ver = "2.1.1-1"
        pkg_ver = "{pkg}_{ver}".format(pkg=pkg, ver=ver)
        self.parser.fixed_packages.append({"package": pkg, "version": ver})
        href = (
            "/archive/debian/20160711T100943Z/pool/main/o/{pkg}/"
            "{pkg_ver}.debian.tar.xz".format(pkg=pkg, pkg_ver=pkg_ver)
        )
        pkg_url = urllib.parse.urljoin("https://snapshot.debian.org", href)
        pkg_name = "{pkg_ver}.debian.tar.xz".format(pkg_ver=pkg_ver)
        pkg_path = os.path.join(settings.DOWNLOAD_DIRECTORY, pkg_name)
        pkg_ext_path = os.path.join(settings.DOWNLOAD_DIRECTORY, pkg_ver)
        mock_page_parse.return_value = {"href": href}

        self.parser.retrieve_packages()
        mock_page_parse.assert_called_once()
        mock_download_method.assert_called_with(pkg_url, pkg_path)
        self.assertIn(
            {"path": pkg_path, "source": pkg_url, "ext_path": pkg_ext_path},
            self.parser.package_paths,
        )

    @unittest.skip("Got to write this properly")
    @mock.patch("patchfinder.parsers.debian_parser.tarfile", spec=tarfile)
    @mock.patch("patchfinder.parsers.debian_parser.os", spec=os)
    def test_extract_patches(
        self,
        mock_os,
        mock_tarfile,
    ):
        path = "foo"
        source = "bar"
        ext_path = "baz"
        members = ["patch.patch", "not_a_patch", "boo.patch"]
        self.parser.vuln_id = "boo"
        self.parser.package_paths.append(
            {"path": path, "source": source, "ext_path": ext_path}
        )
        mock_tarfile.is_tarfile.return_value = True
        mock_tarfile.getmembers.return_value = files
        self.parser.extract_patches()
        mock_tarfile.is_tarfile.assert_called_with(path)
        for f in files:
            self.assertIn(
                {"patch_link": f, "reaching_path": source}, self.parser.patches
            )


if __name__ == "__main__":
    unittest.main()
