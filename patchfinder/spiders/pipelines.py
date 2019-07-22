from scrapy.exporters import JsonItemExporter
import patchfinder.settings as settings


class JsonItemPipeline(object):
    file_name = settings.TEMP_FILE

    def open_spider(self, spider):
        self.file = open(self.file_name, "wb")
        self.exporter = JsonItemExporter(self.file)
        self.exporter.start_exporting()

    def close_spider(self, spider):
        self.exporter.finish_exporting()
        self.file.close()

    def process_item(self, item, spider):
        self.exporter.export_item(item)
        return item


class PatchPipeline(JsonItemPipeline):
    file_name = settings.PATCHES_JSON
