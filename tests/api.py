#!/usr/bin/env python

import os
import sys
import json
import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
from riskiq.api import Client


CONFIG_PATH = os.path.expanduser('~/.config/riskiq')
# # # config = {}
# # # execfile(os.path.join(os.getenv('HOME'), '.creds.py'), config)
CONFIG_FILE = os.path.join(CONFIG_PATH, 'api_config.json')
# # # creds = config['api_creds']['testing']
# # # c = Client(creds['token'], creds['private_key'])
with open(CONFIG_FILE, 'r') as jsonFile:
    _json = (json.load(jsonFile))
cli = Client(_json['api_token'],_json['api_private_key'])

request_filter = [{"field": "name","value": "","type": "EQ"}, {"field": "name","value": "","type": "EQ"}]
request_filters = {"field": "name","value": "","type": "EQ"}
a = cli.post_inventory_search(query='test', filter=request_filter, filters=request_filters)



