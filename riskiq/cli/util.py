#!/usr/bin/env python
import sys
import json
from datetime import datetime, timedelta
from riskiq.render import renderer

try:
    from riskiq import blacklist_stix
    NO_STIX = False
except ImportError:
    NO_STIX = True

def stdin(argv):
    parse_stdin = ('-' in argv)
    if parse_stdin:
        argv = [x for x in argv if x != '-']
        input_lines = sys.stdin.readlines()
        argv += [line.strip() for line in input_lines if line.strip()]
    return argv

def six_hours():
    return (datetime.now() - timedelta(hours=6)).strftime('%Y-%m-%d %H:%M:%S')

def dump_data(data, temp, kwargs):
    # Dump to --stix path
    if kwargs['stix']:
        dump_stix(data, kwargs['stix'])
    elif kwargs['as_json']:
        print(json.dumps(data, indent=4))
    elif data:
        print(
            renderer(data, temp, oneline=kwargs['oneline'],
                verbose=kwargs['verbose']
            )
        )

def templated(temp, yielding=False):
    def deco(func):
        # Simple return of one set of data
        def wrapped(*args, **kwargs):
            data, kwargs2 = func(*args, **kwargs)
            dump_data(data, temp, kwargs2)
        # Handles case where it yields multiple data points
        def wrapped_yielding(*args, **kwargs):
            all_data = {}
            summed = {}
            totalresults = 0
            for data, kwargs2 in func(*args, **kwargs):
                totalresults += data.get('totalResults', 0)
                all_data.update(data)
                for k,v in data.items():
                    if isinstance(v, list):
                        summed[k] = summed.get(k, []) + v
            all_data.update(summed)
            if 'totalResults' in all_data:
                all_data['totalResults'] = totalresults
            dump_data(all_data, temp, kwargs2)
        if yielding:
            return wrapped_yielding
        return wrapped
    return deco
         
def dump_stix(data, path):
    if NO_STIX:
        raise RuntimeError('Please install riskiq[stix]')
    data = blacklist_stix.load_bldata(data)
    output_xml = blacklist_stix.stix_xml(data)
    blacklist_stix.dump_xml(path, output_xml)
    print('Dumped STIX XML to {}'.format(path))

