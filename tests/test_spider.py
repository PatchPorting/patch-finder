import unittest
import unittest.mock as mock
import patchfinder.spiders.default_spider as default_spider
import patchfinder.context as context
import patchfinder.settings as settings
from tests import fake_response_from_file


class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

    def test_start_requests_with_vuln(self):
        """Start requests for a parsable vulnerability.

        For a parsable vulnerability, the spider should generate as
        many requests as the entrypoint URLs for the vulnerability.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.start_requests
        """
        vuln = context.create_vuln("CVE-2016-4796")
        self.spider.set_context(vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(requests), len(vuln.entrypoint_urls))

    def test_start_requests_with_generic_vuln(self):
        """Start requests for an unparsable vulnerability.

        For an unparsable vulnerability, the spider should generate only
        one request, i.e. for the base URL of the vulnerability.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.start_requests
        """
        vuln = context.create_vuln("DSA-4431-1")
        self.spider.set_context(vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url, vuln.base_url)

    def test_parse_response_to_find_patches(self):
        """Upon parsing a response, the yielded items and requests should
        conform to the spider's settings.

        By the default settings, certain URLs present in the selected mock file
        should be absent from the extracted links, certain URLs should be in the
        extracted links, and any patch links in the mock file should be found.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.parse
        """
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
        response = fake_response_from_file(
            "./mocks/3.html", url, meta=settings.PATCH_FIND_META
        )
        response.headers["Content-Type"] = b"text/html"
        requests_and_items = self.spider.parse(response)
        patch_item = next(requests_and_items)
        req_urls = [request.url for request in requests_and_items]
        self.assertEqual(patch_item["patch_link"], patch_link)
        self.assertTrue(all(url not in req_urls) for url in absent_urls)
        self.assertTrue(all(url in req_urls) for url in present_urls)

    def test_determine_aliases_with_no_generic_vulns(self):
        vuln_id = "DSA-4444-1"
        vuln = context.create_vuln(vuln_id)
        expected_aliases = {
            "CVE-2018-12126",
            "CVE-2018-12127",
            "CVE-2018-12130",
            "CVE-2019-11091",
        }
        response = fake_response_from_file(
            "./mocks/debsec_dsa_4444_1.html",
            url="https://security-tracker.debian.org/tracker/{vuln_id}".format(
                vuln_id=vuln_id
            ),
        )
        response.headers["Content-Type"] = b"text/html"
        self.spider.set_context(vuln)
        req_urls = [
            request.url for request in self.spider.determine_aliases(response)
        ]
        got_aliases = set([alias.vuln_id for alias in self.spider.cves])
        self.assertEqual(expected_aliases, got_aliases)
        for cve in self.spider.cves:
            self.assertTrue(url in req_urls for url in cve.entrypoint_urls)

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
