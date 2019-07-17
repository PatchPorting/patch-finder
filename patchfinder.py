import argparse
import logging
from scrapy.crawler import CrawlerProcess
import patchfinder.spiders.default_spider as default_spider
import patchfinder.context as context
import patchfinder.settings as settings

logger = logging.getLogger(__name__)


def spawn_crawler(args):
    vuln = context.create_vuln(args.vuln_id)
    if not vuln:
        return False
    # if args.map_vuln:
        # process = CrawlerProcess({"USER_AGENT": settings.USER_AGENT,
                                  # "EXTENSIONS": settings.EXTENSIONS})
        # process.crawl(vuln_spider.VulnSpider, vuln=vuln)
        # process.start()
    # else:
    process = CrawlerProcess(
        {
            "USER_AGENT": settings.USER_AGENT,
            "ITEM_PIPELINES": {
                "patchfinder.spiders.pipelines.PatchPipeline": 300
            },
            "DEPTH_LIMIT": args.depth,
            "LOG_ENABLED": args.log,
            "EXTENSIONS": settings.EXTENSIONS
        }
    )
    process.crawl(
        default_spider.DefaultSpider,
        vuln=vuln,
        patch_limit=args.patch_limit,
        important_domains=args.imp_domains,
        deny_domains=args.deny_domains,
        debian=args.debian
    )
    process.start()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vuln_id", help="The vulnerability ID to find patches for"
    )
    # parser.add_argument(
        # "-m",
        # "--map-vuln",
        # dest="map_vuln",
        # action="store_true",
        # default=False,
        # help="Map vuln ID to parsable vulnerabilities",
    # )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=settings.DEPTH_LIMIT,
        help="The maximum depth the crawler should go to",
    )
    parser.add_argument(
        "-p",
        "--patch-limit",
        type=int,
        default=settings.PATCH_LIMIT,
        help="The maximum number of patches to be collected",
    )
    parser.add_argument(
        "-dd",
        "--deny-domains",
        nargs="+",
        default=settings.DENY_DOMAINS,
        help="Domains to avoid crawling",
    )
    parser.add_argument(
        "-id",
        "--imp-domains",
        nargs="+",
        default=settings.IMPORTANT_DOMAINS,
        help="Domains to prioritize crawling",
    )
    parser.add_argument(
        "-nl",
        "--no-log",
        dest="log",
        action="store_false",
        help="Disable Scrapy logging",
    )
    parser.add_argument(
        "--no-debian",
        dest="debian",
        action="store_false",
        help="Don't call Debian's parser",
    )
    parser.set_defaults(log=True)
    parser.set_defaults(debian=settings.PARSE_DEBIAN)
    args = parser.parse_args()
    spawn_return = spawn_crawler(args)
    if spawn_return:
        logger.info("Crawling completed.")
    else:
        logger.error("Can't recognize that vulnerability.")
