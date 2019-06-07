import scrapy

class Patch(scrapy.Item):
    patch_link = scrapy.Field()
    reaching_path = scrapy.Field()
