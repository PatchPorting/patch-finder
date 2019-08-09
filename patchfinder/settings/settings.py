from collections.abc import MutableMapping
import patchfinder.settings.scrapy_settings as scrapy_settings
import patchfinder.settings.patchfinder_settings as patchfinder_settings


class Settings(MutableMapping):
    """Base class for settings.

    Inherits from collections.abc.MutableMapping.

    Attributes:
        settings (dict): A dictionary of settings.
        module (Module): A module with default values for settings.
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

    def load_settings(self, settings=dict()):
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

    module = patchfinder_settings


class ScrapySettings(Settings):

    module = scrapy_settings
