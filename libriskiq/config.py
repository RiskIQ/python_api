#!/usr/bin/env python
__author__ = 'jpleger'
import json
import os
CONFIG_PATH = os.path.expanduser('~/.config/riskiq')
CONFIG_FILE = os.path.join(CONFIG_PATH, 'api_config.json')
CONFIG_DEFAULTS = {
    'api_server': 'ws.riskiq.net',
    'api_version': 'v1',
    'api_key': '',
    'api_secret': '',
}


class Config(object):
    def __init__(self, **kwargs):
        self.config = CONFIG_DEFAULTS
        self.load_config(**kwargs)

    def write_config(self):
        json.dump(self.config, open(CONFIG_FILE, 'w'), indent=4, separators=(',', ': '))
        return True

    def load_config(self, **kwargs):
        virgin_config = False
        if not os.path.exists(CONFIG_PATH):
            virgin_config = True
            os.makedirs(CONFIG_PATH)
        if not os.path.exists(CONFIG_FILE):
            virgin_config = True
        if not virgin_config:
            self.config = dict(json.load(open(CONFIG_FILE)))
        if kwargs:
            self.config.update(kwargs)
        if virgin_config or kwargs:
            self.write_config()
        if not self.config['api_key'] or not self.config['api_secret']:
            raise ValueError('API Key or Secret Invalid... Please edit %s' % CONFIG_FILE)
        return True

    @property
    def options(self):
        return self.config.keys()

    def get(self, item, default=None):
        if item in self.config:
            return self.config[item]
        else:
            return default