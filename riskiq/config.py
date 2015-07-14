#!/usr/bin/env python
__author__ = 'jpleger'
import os
import sys
import json

CONFIG_PATH = os.path.expanduser('~/.config/riskiq')
CONFIG_FILE = os.path.join(CONFIG_PATH, 'api_config.json')
CONFIG_DEFAULTS = {
    'api_server': 'ws.riskiq.net',
    'api_version': 'v1',
    'api_token': '',
    'api_private_key': '',
}


class Config(object):
    def __init__(self, **kwargs):
        self.config = CONFIG_DEFAULTS
        try:
            self.load_config(**kwargs)
        except ValueError as e:
            sys.stderr.write('Error: {}\n'.format(e.message))
            sys.exit(1)

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
            # Why dict here? Does an older version of json not do this
            # automatically?
            self.config = dict(json.load(open(CONFIG_FILE)))
        if kwargs:
            self.config.update(kwargs)
        if virgin_config or kwargs:
            self.write_config()
        if 'api_token' not in self.config:
            sys.stderr.write('configure missing API token\n')
        if 'api_private_key' not in self.config:
            sys.stderr.write('configure missing private key\n')
        if not ('api_token' in self.config and 
                'api_private_key' in self.config):
            sys.stderr.write('Errors have been reported. Run riq-config '
                'to fix these warnings.\n')
        return True

    @property
    def options(self):
        return self.config.keys()

    def get(self, item, default=None):
        return self.config.get(item, default)
