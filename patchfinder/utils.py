"""Provides multipurpose utilities used by the patch finder miscellaneously.

Attributes:
    logger: Module level logger.
"""
import logging
import os
import tarfile
import urllib.error
import urllib.request

import lxml.html

from .resource import Resource

logger = logging.getLogger(__name__)


def parse_web_page(url, xpaths=None, links=False):
    """Parse a response returned by a URL.

    The response can be parsed on the basis of xpaths determined by the URL's
    Resource instance or the xpaths given. If the response is to be parsed based
    on the former, the xpaths can be normal or related to link extraction, and
    thus patch-finding/recursion.

    Args:
        url (str): The URL to be parsed.
        xpaths (list[str]): A list of xpaths to parse the response with respect
            to. Defaults to None. If None, the xpaths are taken from the URL's
            corresponding Resource instance.
        links (bool): If True, the links xpaths are used from the corresponding
            Resource, else the normal xpaths are. Defaults to False.

    Returns:
        list[str]: A list of strings scraped from the determined or given
            xpaths.

    Raises:
        Exception: If there is an error in opening the given URL.
    """
    logger.info("Opening %s...", url)
    try:
        html = urllib.request.urlopen(url)
    except urllib.error.HTTPError:
        raise Exception("Error opening {url}".format(url=url))
    logger.info("Crawled %s", url)

    search_results = []
    if not xpaths:
        if not links:
            xpaths = Resource.get_resource(url).normal_xpaths
        else:
            xpaths = Resource.get_resource(url).links_xpaths
    elements = lxml.html.fromstring(html.read())
    for element in elements:
        if element.tag != "body":
            continue
        for xpath in xpaths:
            search_results.extend(element.xpath(xpath))
        break
    return search_results


def download_item(url, save_as, overwrite=False):
    """Download an item

    Args:
        url (str): The url of the item.
        save_as (str): The path to which the item should be saved.
        overwrite (bool): optional argument to overwrite existing file with
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
    """Determine if member is a member of a tarfile.

    Args:
        tar_file (str): The path to the tarfile.
        member (str): Name of the member to be searched for.

    Returns:
        bool: True if member is a member of the tarfile, false otherwise.
    """
    tar = tarfile.open(tar_file)
    try:
        if member in tar.getnames():
            logger.info("%s found in %s", member, tar_file)
            return True
    finally:
        tar.close()
    return False
