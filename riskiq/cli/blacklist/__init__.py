#!/usr/bin/env python
''' riskiq.cli.blacklist
Blacklist endpoint CLI scripts
'''
from argparse import ArgumentParser

from riskiq.api import Client

FILTERS = ('blackhole', 'sakura', 'exploitKit')
CONFIDENCES = ('H', 'M', 'L')

from riskiq.cli.blacklist import (
    lookup, incident, incidentlist, bl_list, malware
)

MAIN_FUNC = {
    'lookup': lookup.run,
    'incident': incident.run,
    'incidentlist': incidentlist.run,
    'list': bl_list.run,
    'malware': malware.run,
}

def main():
    parser = ArgumentParser()
    parser.add_argument('--dump-requests', action='store_true')
    parser.add_argument('--stix',
        help='output results to STIX file (requires riskiq[stix] package)')
    subs = parser.add_subparsers(dest='cmd')
    for module in (lookup, incident, incidentlist, bl_list, malware):
        module.add_parser(subs)
    args = parser.parse_args()

    client = Client.from_config()
    if args.dump_requests:
        client._dump_requests()

    kwargs = {}
    for kwarg in ('as_json', 'oneline', 'stix', 'days', 'start', 'end',
            'verbose', 'timeout', 'six_hours', 'filter', 'confidence',
            'template'):
        if hasattr(args, kwarg):
            kwargs[kwarg] = getattr(args, kwarg)
    
    sub_main = MAIN_FUNC[args.cmd]
    sub_main(client, args, kwargs)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
