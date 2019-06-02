class Provider(object):
    """Base class for a Patch Provider

    Attributes:
    url: The entry url to crawl
    """

    def __init__(self, url):
        self.url = url


class Github(Provider):
    """Subclass for GitHub as a provider"""

    def __init__(self, context):
        url = 'https://github.com/search?q='+context.vuln.vuln_id+'&type=Code'
        super(Github, self).__init__(url)

