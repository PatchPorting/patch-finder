import unittest
import unittest.mock as mock
import patchfinder.spiders.default_spider as default_spider
import patchfinder.context as context
from tests import fake_response_from_file


class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

    def test_start_requests(self):
        vuln = context.create_vuln("CVE-2016-4796")
        self.spider.set_context(vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(vuln.entrypoint_urls), len(requests))

    def test_extract_links(self):
        url = (
            "https://lists.fedoraproject.org/archives/list/package-a"
            "nnounce@lists.fedoraproject.org/message/5FFMOZOF2EI6N"
            "2CR23EQ5EATWLQKBMHW/"
        )
        patch_link = (
            "https://github.com/uclouvain/openjpeg/commit/162"
            "f6199c0cd3ec1c6c6dc65e41b2faab92b2d91.patch"
        )
        absent_urls = [
            "https://docs.fedoraproject.org/yum/",
            "https://fedoraproject.org/keys",
            "https://lists.fedoraproject.org/",
        ]
        present_urls = [
            "https://bugzilla.redhat.com/show_bug.cgi?id=1317822",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1317826",
        ]
        response = fake_response_from_file("./mocks/3.html", url)
        links = self.spider.extract_links(response)
        self.assertTrue(all(url not in links["links"]) for url in absent_urls)
        self.assertTrue(all(url in links["links"]) for url in present_urls)
        self.assertEqual(len(links["patch_links"]), 1)
        self.assertEqual(links["patch_links"], [patch_link])

    def test_parse_response(self):
        self.spider.important_domains.append("github.com")
        response = fake_response_from_file("./mocks/2.html")
        requests_and_items = list(self.spider.parse(response))

        patch_link = (
            "https://github.com/uclouvain/openjpeg/commit/162f619"
            "9c0cd3ec1c6c6dc65e41b2faab92b2d91.patch"
        )
        github_url = "https://github.com/uclouvain/openjpeg/issues/774"
        openwall_url = "http://www.openwall.com/lists/oss-security/2016/05/13/2"

        patch_item = requests_and_items.pop(0)
        self.assertEqual(patch_item["patch_link"], patch_link)
        found_openwall = 0

        for request in requests_and_items:
            if request.url == openwall_url:
                found_openwall = 1
            elif request.url == github_url:
                self.assertEqual(request.priority, 1)
        self.assertTrue(found_openwall)

    @unittest.skip("Redo this")
    def test_patch_limit_with_parse(self):
        self.spider.patch_limit = 2
        secl_response = fake_response_from_file(
            "./mocks/1.html", "https://seclists.org" "/oss-sec/2018/q3/179"
        )
        nvd_response = fake_response_from_file("./mocks/2.html")
        nvd_requests_and_items = list(self.spider.parse(nvd_response))
        secl_requests_and_items = list(self.spider.parse(secl_response))
        self.assertEqual(len(secl_requests_and_items), 1)
        self.assertEqual(len(self.spider.patches), 2)

    @unittest.skip("Redo this")
    def test_parse_html(self):
        vulns = ["CVE-2016-4796", "CVE-2018-20406", "CVE-2019-10017"]
        self.spider.vuln.parse_mode = "html"
        response = fake_response_from_file("./mocks/2.html")
        item = next(self.spider.parse_html(response))
        for vuln in vulns:
            self.assertIn(vuln, item["equivalent_vulns"])

    @unittest.skip("Redo this")
    @mock.patch("patchfinder.spiders.default_spider.utils.json_response_to_xml")
    def test_parse_json(self, mock_json_to_xml):
        vulns = ["CVE-2015-5370", "CVE-2016-2110"]
        self.spider.vuln.xpaths = ["//cve/text()"]
        response = fake_response_from_file("./mocks/mock_json.json")
        xml = (
            b"<cve>CVE-2015-5370</cve><severity>critical</severity>"
            b"<cve>CVE-2016-2110</cve><severity>moderate</severity>"
        )
        mock_json_to_xml.return_value = response.replace(body=xml)

        item = next(self.spider.parse_json(response))
        for vuln in vulns:
            self.assertIn(vuln, item)

    @unittest.skip("Redo this")
    @mock.patch("patchfinder.spiders.default_spider.utils.parse_file_by_block")
    @mock.patch(
        "patchfinder.spiders.default_spider.utils.write_response_to_file"
    )
    def test_parse_plain_as_per_block(
        self, mock_write_response_method, mock_parse_file_method
    ):
        self.spider.vuln.as_per_block = True
        self.spider.vuln.start_block = None
        self.spider.vuln.end_block = None
        self.spider.vuln.search_params = None
        vulns = ["CVE-2019-11707 CVE-2019-11708"]
        mock_parse_file_method.return_value = [equivalent_vulns]
        response = fake_response_from_file("./mocks/mock_debian_dsa_list")
        item = next(self.spider.parse_plain(response))
        self.assertEqual(item, equivalent_vulns)

    @unittest.skip("Redo this")
    def test_no_debian_callback(self):
        self.spider.debian = False
        debian_url = (
            "https://security-tracker.debian.org/tracker/CVE-2018" "-1000156"
        )
        callback = self.spider.callback(debian_url)
        self.assertEqual(callback.__name__, "parse")

    @unittest.skip("Redo this")
    def test_debian_callback(self):
        self.spider.debian = True
        debian_url = (
            "https://security-tracker.debian.org/tracker/CVE-2018" "-1000156"
        )
        callback = self.spider.callback(debian_url)
        self.assertEqual(callback.__name__, "parse_debian")

    @unittest.skip("Redo this")
    def test_callback_html(self):
        self.spider.vuln.parse_mode = "html"
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, "parse_html")

    @unittest.skip("Redo this")
    def test_callback_json(self):
        self.spider.vuln.parse_mode = "json"
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, "parse_json")

    @unittest.skip("Redo this")
    def test_callback_plain(self):
        self.spider.vuln.parse_mode = "plain"
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, "parse_plain")


if __name__ == "__main__":
    unittest.main()
