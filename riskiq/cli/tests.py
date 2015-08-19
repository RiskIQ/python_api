#!/usr/bin/env python
''' riskiq.cli.tests
Unit tests using nose
'''
import sys
import os
import json
from StringIO import StringIO
from mock import MagicMock
from nose import with_setup

ROOT_DIR = os.path.dirname(__file__)

def load_data(filename):
    path = os.path.join(ROOT_DIR, 'testdata', filename)
    with open(path) as f:
        return json.load(f)

RETURN_VALUES = {
    'blacklist_incident': load_data('zief.pl.json'),
}

GLOBALS = {}

def ret_val(x):
    return RETURN_VALUES[x]

def setup_blacklist():
    client = MagicMock()
    client.get_blacklist_incident.return_value = ret_val('blacklist_incident')
    args = MagicMock()
    args.urls = ['zief.pl']
    stdout = sys.stdout
    buf = StringIO()
    sys.stdout = buf
    GLOBALS['client'] = client
    GLOBALS['args'] = args
    GLOBALS['stdout'] = stdout
    GLOBALS['buf'] = buf

def teardown_blacklist():
    sys.stdout = GLOBALS['stdout']

@with_setup(setup_blacklist, teardown_blacklist)
def test_bl_incident_oneline():
    from riskiq.cli.blacklist.incident import run
    client, args = GLOBALS['client'], GLOBALS['args']
    kwargs = {'oneline': True}
    run(client, args, kwargs)
    out = GLOBALS['buf'].read()
