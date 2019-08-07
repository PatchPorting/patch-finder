import unittest
from scrapy.http import Request
import patchfinder.spiders.default_spider as default_spider
import patchfinder.spiders.items as items
import patchfinder.context as context
import patchfinder.settings as settings
from tests import fake_response


class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

    def test_start_requests_with_vuln(self):
        """Start requests for a normal vulnerability.

        For a normal vulnerability (i.e. a CVE), the spider should generate as
        many requests as the entrypoint URLs for the vulnerability.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.start_requests
        """
        vuln = context.create_vuln("CVE-2016-4796")
        self.spider.set_context(vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(requests), len(vuln.entrypoint_urls))

    def test_start_requests_with_generic_vuln(self):
        """Start requests for a generic vulnerability.

        For a generic vulnerability, the spider should generate only
        one request, i.e. for the base URL of the vulnerability.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.start_requests
        """
        vuln = context.create_vuln("DSA-4431-1")
        self.spider.set_context(vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url, vuln.base_url)

    def test_parse_response_to_find_patches_with_fedora_list_url(self):
        """Items and requests yielded should conform to spider's settings.

        By the default settings, certain URLs present in the selected mock file
        should be absent from the extracted links, certain URLs should be in the
        extracted links, and any patch links in the mock file should be found.

        Tests:
            patchfinder.spiders.base_spider.BaseSpider.parse
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
        response = fake_response(
            file_name="./mocks/3.html",
            url=url,
            meta=settings.PATCH_FIND_META,
            content_type=b"text/html",
        )
        requests_and_items = self.spider.parse(response)
        patch_item = next(requests_and_items)
        req_urls = [request.url for request in requests_and_items]
        self.assertEqual(patch_item["patch_link"], patch_link)
        self.assertTrue(all(url not in req_urls) for url in absent_urls)
        self.assertTrue(all(url in req_urls) for url in present_urls)

    def test_parse_response_with_no_links_to_find_patches(self):
        """Parse a response with no links to find patches.

        No Requests or Items should be generated.

        Tests:
            patchfinder.spiders.base_spider.BaseSpider.parse
        """
        response = fake_response(
            file_name="./mocks/debsec_cve_2017_1088.html",
            url="https://security-tracker.debian.org/tracker/CVE-2017-1088",
            meta=settings.PATCH_FIND_META,
            content_type=b"text/html",
        )
        requests_and_items = list(self.spider.parse(response))
        self.assertFalse(requests_and_items)

    def test_parse_response_with_only_patch_links(self):
        """Spider should yield only Patch items.

        Tests:
            patchfinder.spiders.base_spider.BaseSpider.parse
        """
        response = fake_response(
            file_name="./mocks/debsec_cve_2019_14452.html",
            url="https://security-tracker.debian.org/tracker/CVE-2019-14452",
            meta=settings.PATCH_FIND_META,
            content_type=b"text/html",
        )
        requests_and_items = list(self.spider.parse(response))
        self.assertTrue(requests_and_items)
        for item in requests_and_items:
            self.assertIsInstance(item, items.Patch)

    def test_parse_response_with_only_links(self):
        """Spider should yield only Requests.

        Tests:
            patchfinder.spiders.base_spider.BaseSpider.parse
        """
        response = fake_response(
            file_name="./mocks/debsec_cve_2019_12594.html",
            url="https://security-tracker.debian.org/tracker/CVE-2019-12594",
            meta=settings.PATCH_FIND_META,
            content_type=b"text/html",
        )
        requests_and_items = list(self.spider.parse(response))
        self.assertTrue(requests_and_items)
        for item in requests_and_items:
            self.assertIsInstance(item, Request)

    def test_parse_json_response_with_redhat_secapi_url(self):
        """Parse a JSON response.

        Tests:
            patchfinder.spiders.base_spider.BaseSpider.parse_json
        """
        response = fake_response(
            file_name="./mocks/mock_json.json",
            url="https://access.redhat.com/labs/securitydataapi/cve.json?"
            "advisory=foobar",
            content_type=b"application/json",
        )
        expected_items = {"CVE-2015-5370", "CVE-2016-2110"}
        requests_and_items = set(self.spider.parse(response))
        self.assertEqual(requests_and_items, expected_items)

    def test_determine_aliases_with_no_generic_vulns(self):
        """The aliases of a vulnerability should be scraped from the response.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.determine_aliases
        """
        vuln_id = "DSA-4444-1"
        vuln = context.create_vuln(vuln_id)
        expected_aliases = {
            "CVE-2018-12126",
            "CVE-2018-12127",
            "CVE-2018-12130",
            "CVE-2019-11091",
        }
        response = fake_response(
            file_name="./mocks/debsec_dsa_4444_1.html",
            url=vuln.base_url,
            content_type=b"text/html",
        )
        self.spider.set_context(vuln)
        req_urls = [
            request.url for request in self.spider.determine_aliases(response)
        ]
        got_aliases = set(alias.vuln_id for alias in self.spider.cves)
        self.assertEqual(expected_aliases, got_aliases)
        for cve in self.spider.cves:
            self.assertTrue(url in req_urls for url in cve.entrypoint_urls)

    def test_determine_aliases_with_generic_vulns_and_cves(self):
        """Aliases should be scraped and requests for generic vulns generated.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.determine_aliases
        """
        vuln_id = "GLSA-200602-01"
        vuln = context.create_vuln(vuln_id)
        expected_aliases = {"CVE-2005-4048"}
        response = fake_response(
            file_name="./mocks/gentoo_glsa_200602_01.xml",
            url=vuln.base_url,
            # The response content-type Scrapy gets for this URL is text/plain.
            content_type=b"text/plain",
        )

        self.spider.set_context(vuln)
        req_urls = [
            request.url for request in self.spider.determine_aliases(response)
        ]
        got_aliases = set(alias.vuln_id for alias in self.spider.cves)
        self.assertEqual(expected_aliases, got_aliases)

        # Requests for generic vulnerabilities found should be yielded.
        self.assertIn(
            "https://gitweb.gentoo.org/data/glsa.git/plain/glsa-200601-06.xml",
            req_urls,
        )
        for cve in self.spider.cves:
            self.assertTrue(url in req_urls for url in cve.entrypoint_urls)

    def test_determine_aliases_with_no_aliases_in_response(self):
        """No aliases and no vulerabilities should be scraped.

        Tests:
            patchfinder.spiders.default_spider.DefaultSpider.determine_aliases
        """
        vuln_id = "GLSA-200311-04"
        vuln = context.create_vuln(vuln_id)
        response = fake_response(
            file_name="./mocks/gentoo_glsa_200311_04.xml",
            url=vuln.base_url,
            # The response content-type Scrapy gets for this URL is text/plain.
            content_type=b"text/plain",
        )

        self.spider.set_context(vuln)
        req_urls = [
            request.url for request in self.spider.determine_aliases(response)
        ]
        self.assertFalse(self.spider.cves)
        self.assertFalse(req_urls)


if __name__ == "__main__":
    unittest.main()
