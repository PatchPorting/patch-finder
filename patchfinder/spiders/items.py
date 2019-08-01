"""Provides Scrapy Item classes used by the spider."""
import scrapy


class Patch(scrapy.Item):
    patch_link = scrapy.Field()
    reaching_path = scrapy.Field()
