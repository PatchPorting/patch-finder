"""Provides pipelines for use by the spider."""
from scrapy.exporters import JsonItemExporter

from patchfinder.settings import PatchfinderSettings


class JsonItemPipeline:

    def open_spider(self, spider):
        self.file = open(self.file_name, "wb")
        self.exporter = JsonItemExporter(self.file, indent=4)
        self.exporter.start_exporting()

    def close_spider(self, spider):
        self.exporter.finish_exporting()
        self.file.close()

    def process_item(self, item, spider):
        self.exporter.export_item(item)
        return item


class PatchPipeline(JsonItemPipeline):
    # Temporary hack
    file_name = PatchfinderSettings()["PATCHES_JSON"]
