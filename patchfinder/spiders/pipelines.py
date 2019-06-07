import json

class PatchPipeline(object):

    def open_spider(self, spider):
        self.file = open('patches.json', 'w')

    def close_spider(self, spider):
        self.file.close()

    def process_item(self, item, spider):
        line = json.dumps(dict(item)) + '\n'
        self.file.write(line)
        return item
