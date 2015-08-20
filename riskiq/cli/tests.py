#!/usr/bin/env python
''' riskiq.cli.tests
Unit tests using nose
'''
import sys
import os
import json
from mock import MagicMock
from nose import with_setup

ROOT_DIR = os.path.dirname(__file__)

def load_data(filename):
    path = os.path.join(ROOT_DIR, 'testdata', filename)
    with open(path) as f:
        data = json.load(f)
    return data

def read(filename):
    path = os.path.join(ROOT_DIR, 'testdata', 'output', filename)
    with open(path) as f:
        return f.read().strip()

RETURN_VALUES = {
    'blacklist_incident': load_data('zief.pl.json'),
    'blacklist_list': load_data('bl_list.json'),
}

ASSERT_VALUES = {
    'blacklist_list.oneline': read('bl_list.oneline'),
    'blacklist_incident.oneline': read('bl_incident.oneline'),
}

MOCKED_OBJECTS = {}

def assert_val(x):
    return ASSERT_VALUES[x]

def ret_val(x):
    return RETURN_VALUES[x]

def setup_blacklist():
    client = MagicMock()
    client.get_blacklist_incident.return_value = ret_val('blacklist_incident')
    client.get_blacklist_list.return_value = ret_val('blacklist_list')
    args = MagicMock()
    args.urls = ['zief.pl']
    args.start_index = None
    args.max_results = None
    MOCKED_OBJECTS['client'] = client
    MOCKED_OBJECTS['args'] = args

def teardown_blacklist():
    pass

@with_setup(setup_blacklist, teardown_blacklist)
def test_bl_incident_oneline():
    from riskiq.cli.blacklist.incident import run
    client, args = MOCKED_OBJECTS['client'], MOCKED_OBJECTS['args']
    output = run(client, args, {'oneline': True, 'return_output': True})
    good = assert_val('blacklist_incident.oneline')
    print('\ngood: {}'.format(good))
    print('bad:  {}'.format(output))
    assert output == good

@with_setup(setup_blacklist, teardown_blacklist)
def test_bl_list_oneline():
    from riskiq.cli.blacklist.bl_list import run
    client, args = MOCKED_OBJECTS['client'], MOCKED_OBJECTS['args']
    output = run(client, args, {'oneline': True, 'filter': None, 'return_output': True})
    good = assert_val('blacklist_list.oneline')
    print('\ngood: {}'.format(good))
    print('bad:  {}'.format(output))
    assert output == good
