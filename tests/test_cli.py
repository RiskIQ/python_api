#!/usr/bin/env python
''' riskiq.cli.tests
Unit tests using nose
'''
import types
import sys
import os
import json
import re
from functools import wraps
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
    #'blacklist_list': read('bl_list'),
    'blacklist_list.oneline': read('bl_list.oneline'),
    'blacklist_incident.oneline': read('bl_incident.oneline'),
    'blacklist_incident': read('bl_incident'),
}

MOCKED_OBJECTS = {}

def assert_val(x):
    return ASSERT_VALUES[x]

def ret_val(x):
    return RETURN_VALUES[x]

def setup(func):
    if not isinstance(func, types.FunctionType):
        return
    match = re.match(r'test_blacklist_(?P<module_name>[a-zA-Z0-9]+)(?:_(?P<template>\w+))?',
        func.func_name)
    module_name = match.group('module_name') 
    template = match.group('template')
    func.template = template
    if template is not None:
        func.assert_template = 'blacklist_{}.{}'.format(module_name, template)
    else:
        func.assert_template = 'blacklist_' + module_name
    if module_name == 'list':
        module_name = 'bl_list'
    func.mod_name = module_name
    func.client = MagicMock()
    func.client.get_blacklist_incident.return_value = ret_val('blacklist_incident')
    func.client.get_blacklist_list.return_value = ret_val('blacklist_list')
    func.args = MagicMock()
    func.args.urls = ['zief.pl']
    func.args.start_index = None
    func.args.max_results = None
    @wraps(func)
    def created_test():
        good = assert_val(func.assert_template)
        kwargs = {'return_output': True, 'filter': None}
        kwargs[func.template] = True
        mod = __import__('riskiq.cli.blacklist.{}'.format(func.mod_name))
        mod = getattr(mod.cli.blacklist, func.mod_name)
        run = getattr(mod, 'run')
        output = run(func.client, func.args, kwargs)
        if output != good:
            fname = 'nosetests.{}.output'.format(func.func_name)
            with open(fname + '.orig', 'w') as f:
                f.write(good)
            with open(fname + '.rej', 'w') as f:
                f.write(output)
        assert output == good
        func()
    return created_test

@setup
def test_blacklist_incident_oneline():
    pass

@setup
def test_blacklist_list_oneline():
    pass

@setup
def test_blacklist_incident():
    pass

'''
@setup
def test_blacklist_list():
    pass
'''
