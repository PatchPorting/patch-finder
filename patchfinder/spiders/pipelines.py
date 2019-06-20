import json
import patchfinder.settings as settings

class PatchPipeline(object):

    def open_spider(self, spider):
        self.file = open(settings.PATCHES_JSON, 'w')

    def close_spider(self, spider):
        self.file.close()

    def process_item(self, item, spider):
        line = json.dumps(dict(item)) + '\n'
        self.file.write(line)
        return item
