import os
import re
import logging
import urllib.request

logger = logging.getLogger(__name__)


def match_all(string, patterns):
    if all(re.search(x, string) for x in patterns):
        return True
    return False


def match_any(string, patterns):
    if any(re.search(x, string) for x in patterns):
        return True
    return False


def parse_raw_file(file_name, start_block, end_block, search_params):
    f = open(file_name)
    try:
        block_found = False
        for line in f:
            if block_found:
                if end_block.match(line):
                    break
                search_results = search_params.search(line)
                if search_results:
                    yield search_results
            elif start_block.match(line):
                block_found = True
    finally:
        f.close()


def download_item(url, save_as, overwrite=False):
    """Download an item

    Args:
        url: The url of the item
        save_as: The path to which the item should be saved
        overwrite: optional argument to overwrite existing file with
            same name as save_as. If overwrite is True, the file will
            be downloaded from url and the existing file will be
            overwritten.
    """
    logger.info("Downloading %s as %s...", url, save_as)
    if os.path.isfile(save_as) and not overwrite:
        logger.info("%s exists, not overwriting", save_as)
        return
    parent_dir = os.path.split(save_as)[0]
    if not os.path.isdir(parent_dir):
        os.makedirs(parent_dir)
    urllib.request.urlretrieve(url, save_as)
    logger.info("Downloaded %s...", url)
