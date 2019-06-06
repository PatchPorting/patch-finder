from scrapy.Spiders import CrawlSpider
import entrypoint
import context

class DefaultSpider(CrawlSpider):
    
    def __init__(self, vuln, recursion_limit=0):
        self.entrypoints = vuln.entrypoints
        self.recursion_limit = recursion_limit
        self.visited_urls = []
        self.entrypoint_stack = []
        self.patches = []
        self.current_path = []

    def start_requests(self):
        for entrypoint in self.entrypoints:
            self.entrypoint_stack.append(entrypoint)
            for url in entrypoint.urls:
                yield Request(url, callback=self.parse)

    def parse(self, response):
        links = response.css('a::attr(href)')
        for link in links:
            if entrypoint.is_patch(link):
                if not any(x.patch_link is link for x in self.patches):
                    self.add_patch(link)

    def add_to_path(self, url):
        self.current_path.append(url)

    def pop_from_path(self, url):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(context.Patch(self.current_path, patch_link))
