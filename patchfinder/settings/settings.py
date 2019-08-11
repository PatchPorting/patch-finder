"""Provides classes for settings.

This module provides a Base Settings class, and its subclasses for the
patch-finder and for Scrapy.
"""
from collections.abc import MutableMapping

from patchfinder.settings import patchfinder_settings, scrapy_settings


class Settings(MutableMapping):
    """Base class for settings.

    The default settings are taken from a default module. Variable names of the
    default settings must be uppercase for the settings to be read.

    A dictionary of settings is taken and set in the Settings' instance.
    Any other values are taken from the default module and set. Values given
    to the instance specifically are not overwritten by these default settings.

    Attributes:
        settings (dict): A dictionary of settings.
        module (module): A module with default values for settings.
    """

    module = None

    def __init__(self, **kwargs):
        self.settings = kwargs.get("settings", dict())
        if not self.module:
            self.module = kwargs.get("module")
        self._load_settings_from_module()

    def __getitem__(self, name):
        return self.settings.get(name)

    def __setitem__(self, name, value):
        self.settings[name] = value

    def __delitem__(self, name):
        del self.settings[name]

    def __len__(self):
        return len(self.settings)

    def __iter__(self):
        return iter(self.settings)

    def load_settings(self, settings=None):
        """Load settings into the Settings' instance.

        The settings are first set from the given dictionary. After that,
        any missing settings are taken from the default settings module.

        Args:
            settings (dict): The settings to be set in the instance. Defaults
                to None.
        """
        if settings:
            for key in settings:
                self.settings[key] = settings[key]
        self._load_settings_from_module()

    def _load_settings_from_module(self):
        if not self.module:
            return
        for setting in dir(self.module):
            if setting.isupper() and setting not in self.settings:
                self.settings[setting] = getattr(self.module, setting)


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
