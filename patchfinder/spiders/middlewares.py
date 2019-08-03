from scrapy import signals
from scrapy.http import Request

class DepthResetMiddleware(object):
    @classmethod
    def from_crawler(cls, crawler):
        s = cls()
        return s

    def process_spider_output(self, response, result, spider):
        for obj in result:
            if not isinstance(obj, Request):
                yield obj
                continue
            if (
                "depth" in obj.meta
                and "reset_depth" in obj.meta
                and obj.meta["reset_depth"]
            ):
                obj.meta["depth"] = 0
            yield obj
