import unittest

import patchfinder.resource as resource
from patchfinder.resource import Resource


class TestResource(unittest.TestCase):
    """Test Class for the resource module."""

    def test_github_match_link(self):
        github = resource.Github()
        links = [
            "https://github.com/python/cpython/commit/a4ae828ee416a6"
            "6d8c7bf5ee71d653c2cc6a26dd",
            "https://github.com/python/cpython/pull/13797",
        ]
        self.assertTrue(github.match_link(link) for link in links)

    def test_github_is_patch(self):
        link = (
            "https://github.com/uclouvain/openjpeg/commit/162f6199c"
            "0cd3ec1c6c6dc65e41b2faab92b2d91"
        )
        patch_link = resource.is_patch(link)
        self.assertEqual(patch_link, link + ".patch")

    def test_pagure_is_patch(self):
        link = "https://pagure.io/389-ds-base/c/4d9cc24da"
        patch_link = resource.is_patch(link)
        self.assertEqual(patch_link, link + ".patch")

    def test_bitbucket_is_patch(self):
        link = (
            "https://bitbucket.org/mpyne/game-music-emu/commits/"
            "205290614cdc057541b26adeea05a9d45993f860"
        )
        patch_link = resource.is_patch(link)
        self.assertEqual(patch_link, link + "/raw")

    def test_mitre_url_mapping(self):
        url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4796"
        resource = Resource.get_resource(url)

    def test_openwall_url_mapping(self):
        url = "https://www.openwall.com/lists/oss-security/2016/05/13/2"
        resource = Resource.get_resource(url)

    def test_fedoraproject_lists_url_mapping(self):
        url = (
            "https://lists.fedoraproject.org/archives/list/package-announ"
            "ce@lists.fedoraproject.org/message/5FFMOZOF2EI6N2CR23EQ5EA"
            "TWLQKBMHW/"
        )
        resource = Resource.get_resource(url)

    def test_debian_lists_url_mapping(self):
        url = (
            "https://lists.debian.org/debian-lts-announce/2019/05/msg0003"
            "9.html"
        )
        resource = Resource.get_resource(url)

    def test_seclists_url_mapping(self):
        url = "https://seclists.org/oss-sec/2018/q3/179"
        resource = Resource.get_resource(url)


if __name__ == "__main__":
    unittest.main()
