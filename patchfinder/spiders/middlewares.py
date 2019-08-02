import pdb
from scrapy import signals
from scrapy.http import Request

class DepthResetMiddleware(object):
    @classmethod
    def from_crawler(cls, crawler):
        s = cls()
        return s

    def process_spider_output(self, response, result, spider):
        for r in result:
            if not isinstance(r, Request):
                yield r
                continue
            if (
                "depth" in r.meta
                and "reset_depth" in r.meta
                and r.meta["reset_depth"]
            ):
                r.meta["depth"] = 0
            yield r
