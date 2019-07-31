"""Provides multipurpose utilities used by the patch finder miscellaneously.

Attributes:
    logger: Module level logger.
"""
import os
import re
import logging
import json
import tarfile
import urllib.request
import urllib.error
import lxml
from .entrypoint import Resource

logger = logging.getLogger(__name__)


def parse_web_page(url, xpaths=None, links=False):
    logger.info("Opening %s...", url)
    try:
        html = urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        raise Exception("Error opening {url}".format(url=url))
    logger.info("Crawled %s", url)

    search_results = []
    if not xpaths:
        if not links:
            xpaths = Resource.get_resource(url).get_normal_xpaths()
        else:
            xpaths = Resource.get_resource(url).get_link_xpaths()
    elements = lxml.html.fromstring(html.read())
    for element in elements:
        if element.tag != "body":
            continue
        for xpath in xpaths:
            search_results.extend(element.xpath(xpath))
        break
    return search_results


def parse_dict(dictionary, key_list, get_key=False):
    if not key_list:
        return []
    search_results = []
    for key in dictionary.keys():
        if not re.match(key_list[0], key):
            continue
        if len(key_list) == 1:
            if get_key:
                search_results.append(key)
            else:
                search_results.append(dictionary[key])
        else:
            search_results.extend(
                parse_dict(dictionary[key], key_list[1:], get_key)
            )
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
