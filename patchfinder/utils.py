import os
import re
import logging
import tarfile
import urllib.request
import urllib.error
from bs4 import BeautifulSoup

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


def parse_web_page(url, tag, **search_params):
    try:
        html = urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        raise Exception("Error opening {url}".format(url=url))
    logger.info("Crawled %s", url)
    soup = BeautifulSoup(html, 'html.parser')

    #currently returns only one item, use find_all for multiple
    search_results = soup.find(tag, **search_params)
    return search_results


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


def member_in_tarfile(tar_file, member):
    """Determine if member is a member of a tarfile

    Args:
        tar_file: The path to the tarfile
        member: Name of the member to be searched for

    Returns:
        True if member is a member of the tarfile, false otherwise
    """
    tar = tarfile.open(tar_file)
    try:
        if member in tar.getnames():
            logger.info("%s found in %s", member, tar_file)
            return True
    finally:
        tar.close()
    return False


#NOTE: This method could use a recursive and regex based search
def find_in_directory(directory, file_name):
    """Look for a file in a directory

    If multiple files which have the given file name in their names are
    found, these are also returned.

    Args:
        directory: The path to the directory
        file_name: Name of the file to be searched for

    Yields:
        Files with file_name in their names
    """
    if not os.path.isdir(directory):
        logger.info("Can't find %s", directory)
        return
    logger.info("Looking for %s in %s", file_name, directory)
    for f in os.listdir(directory):
        if f.find(file_name) is not -1:
            logger.info("Found: %s", f)
            yield os.path.join(directory, f)
