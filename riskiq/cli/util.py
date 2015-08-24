#!/usr/bin/env python
import sys
import json
import re
from datetime import datetime, timedelta
from riskiq.render import renderer
try:
    from pytz.reference import Pacific
except ImportError:
    Pacific = None

try:
    from riskiq import blacklist_stix
    NO_STIX = False
except ImportError:
    NO_STIX = True

RE_TIMESTAMP = re.compile(r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}).(?P<millisecond>\d{3})(?P<timezone>[+-]\d{4})')

def dt_from_timestamp(ts):
    match = RE_TIMESTAMP.match(ts)
    if not match:
        return None
    dtdict = match.groupdict()
    dtdict['microsecond'] = int(dtdict['millisecond']) * 1000
    del dtdict['millisecond']
    del dtdict['timezone']
    dtdict = {k: int(v) for k,v in dtdict.items()}
    if Pacific is not None:
        # Assume Pacific/-0800 for now
        tzinfo = Pacific
        dtdict['tzinfo'] = tzinfo
    return datetime(**dtdict)

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
    ret_out = kwargs.get('return_output')
    if kwargs.get('stix'):
        dump_stix(data, kwargs['stix'])
        return kwargs['stix']
    elif kwargs.get('as_json'):
        val = json.dumps(data, indent=4)
    elif data:
        val = renderer(data, temp, 
                oneline=kwargs.get('oneline', False),
                verbose=kwargs.get('verbose', False),
                custom_template=kwargs.get('template'),
            )
    print(val)
    if ret_out:
        return val

def templated(temp, yielding=False):
    def deco(func):
        # Simple return of one set of data
        def wrapped(*args, **kwargs):
            data, kwargs2 = func(*args, **kwargs)
            return dump_data(data, temp, kwargs2)
        # Handles case where it yields multiple data points
        def wrapped_yielding(*args, **kwargs):
            all_data = {}
            kwargs2 = {}
            for data, kwargs2 in func(*args, **kwargs):
                all_data.update(data)
            return dump_data(all_data, temp, kwargs2)
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

