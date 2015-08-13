#!/usr/bin/env python
import sys
from datetime import datetime, timedelta
from riskiq.render import renderer
from riskiq.cli.blacklist import dump_stix

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

def templated(temp, yielding=False):
    def deco(func):
        def wrapped(*args, **kwargs):
            data, kwargs2 = func(*args, **kwargs)
            # Dump to --stix path
            if kwargs2['stix']:
                dump_stix(data, kwargs2['stix'])
            elif kwargs2['as_json']:
                print(json.dumps(data, indent=4))
            elif data:
                print(
                    renderer(data, temp, oneline=kwargs2['oneline'],
                        verbose=kwargs2['verbose']
                    )
                )

        def wrapped_yielding(*args, **kwargs):
            for data, kwargs2 in func(*args, **kwargs):
                # Dump to --stix path
                if kwargs2['stix']:
                    dump_stix(data, kwargs2['stix'])
                elif kwargs2['as_json']:
                    print(json.dumps(data, indent=4))
                elif data:
                    print(
                        renderer(data, temp, oneline=kwargs2['oneline'],
                            verbose=kwargs2['verbose']
                        )
                    )
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

