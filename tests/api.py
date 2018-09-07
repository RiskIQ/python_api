#!/usr/bin/env python

import os
from api import Client

config = {}
execfile(os.path.join(os.getenv('HOME'), '.creds.py'), config)

creds = config['api_creds']['testing']
c = Client(creds['token'], creds['private_key'])


