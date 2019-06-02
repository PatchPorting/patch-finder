import unittest
import patchfinder.context as context
import patchfinder.provider as provider

class TestVulnerability(unittest.TestCase):
    """Test Class for Vulnerability"""

    def test_provider_init(self):
        ctx = context.create_context('CVE-2018-20406')
        prov = provider.Github(ctx)
        self.assertEqual(prov.url,'https://github.com/search?q=CVE-2018-20406&type=Code')


if __name__ == '__main__':
    unittest.main()
