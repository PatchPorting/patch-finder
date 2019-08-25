"""Module used for interacting with the patch-finder.

Attributes:
    logger: Module level logger.
"""
import argparse
import logging

from scrapy.crawler import CrawlerProcess

import patchfinder.context as context
import patchfinder.spiders.default_spider as default_spider
from patchfinder.settings import PatchfinderSettings, ScrapySettings

logger = logging.getLogger(__name__)


def spawn_crawler(args):
    vuln = context.create_vuln(args["vuln_id"])
    scrapy_settings = dict(ScrapySettings(values=args))
    patchfinder_settings = dict(PatchfinderSettings(values=args))
    if not vuln:
        return False
    process = CrawlerProcess(scrapy_settings)
    process.crawl(
        default_spider.DefaultSpider, vuln=vuln, settings=patchfinder_settings
    )
    process.start()
    return True

def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vuln_id",
        help="The vulnerability ID to find patches for",
    )
    parser.add_argument(
        "-d",
        "--depth-limit",
        dest="DEPTH_LIMIT",
        type=int,
        help="The maximum depth the crawler should go to."
    )
    parser.add_argument(
        "-p",
        "--patch-limit",
        dest="PATCH_LIMIT",
        type=int,
        help="The maximum number of patches to collect."
    )
    return parser

def main():
    parser = argument_parser()
    args = parser.parse_args()

    # Filter out arguments that weren't used.
    # This is so that None is not used for the respective settings.
    args = {k: v for k, v in vars(args).items() if v is not None}
    spawn_return = spawn_crawler(args)
    if spawn_return:
        logger.info("Crawling completed.")
    else:
        logger.error("Can't recognize that vulnerability.")

if __name__ == "__main__":
    main()
