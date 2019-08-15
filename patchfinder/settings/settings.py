"""Provides classes for settings.

This module provides a Base Settings class, and its subclasses for the
patch-finder and for Scrapy.
"""
import six

from scrapy.settings import BaseSettings

from patchfinder.settings import patchfinder_settings, scrapy_settings


class Settings(BaseSettings):
    """Base class for settings.

    This class extends Scrapy's BaseSettings class. The BaseSettings class
    extends collections' MutableMapping abstract class, so this class is also
    a MutableMapping abstract class.

    The default settings are taken from a default module. Variable names of the
    default settings must be uppercase for the settings to be read. Thus, only
    variables in uppercase are taken as settings and set in the instance.

    A dictionary of settings is taken and set in the Settings' instance.
    Default values are taken from the given module, i.e., values are initially
    taken from the module. Specific settings given then overwrite their
    respective default values.

    Settings given in the values argument that are unrecognized, i.e., those
    settings that are not present in the default module, are not set in the
    instance.

    Attributes:
        module (module): A module with default values for settings.
    """

    module = None

    def __init__(self, module=None, values=None, priority="project"):
        super(Settings, self).__init__()
        if module:
            self.module = module
        if self.module:
            self.setmodule(self.module, "default")
        for name, val in six.iteritems(self):
            self.set(name, val, "default")
        values = self._filter_values(values)
        self.update(values, priority)

    # if an unrecognized setting is given, should an error be raised?
    def _filter_values(self, values=None):
        if values:
            return {k: v for k, v in values.items() if k in self}
        return None


class PatchfinderSettings(Settings):
    """Settings for the patch-finder, i.e., for the spider.

    These settings are meant to be for user preferences in the patch-finding
    operation.
    """

    module = patchfinder_settings


class ScrapySettings(Settings):
    """Settings for Scrapy.

    These settings will be fed to the CrawlerProcess, which would initiate
    the crawling.
    """

    module = scrapy_settings
