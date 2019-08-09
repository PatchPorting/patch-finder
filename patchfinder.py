"""Module used for interacting with the patch-finder.

Attributes:
    logger: Module level logger.
"""
import argparse
import logging
from scrapy.crawler import CrawlerProcess
import patchfinder.spiders.default_spider as default_spider
import patchfinder.context as context
from patchfinder.settings import PatchfinderSettings, ScrapySettings

logger = logging.getLogger(__name__)


def spawn_crawler(args):
    vuln = context.create_vuln(args.vuln_id)
    scrapy_settings = dict(ScrapySettings())
    patchfinder_settings = dict(PatchfinderSettings())
    if not vuln:
        return False
    process = CrawlerProcess(scrapy_settings)
    process.crawl(
        default_spider.DefaultSpider, vuln=vuln, settings=patchfinder_settings
    )
    process.start()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vuln_id",
        help="The vulnerability ID to find patches for",
    )
    args = parser.parse_args()
    spawn_return = spawn_crawler(args)
    if spawn_return:
        logger.info("Crawling completed.")
    else:
        logger.error("Can't recognize that vulnerability.")
