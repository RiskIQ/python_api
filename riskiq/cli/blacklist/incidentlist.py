#!/usr/bin/env python
''' riskiq.cli.blacklist.incidentlist
'''
from riskiq.cli.util import templated, six_hours
from riskiq.cli.parser import add_timerange_args, add_render_args

def add_parser(subs):
    parser = subs.add_parser('incidentlist',
        help='query blacklist incidents within given timeframe')
    parser.add_argument('--all-workspace-crawls', '-a',
        action='store_true', help='filter crawls to those on workspace')
    parser.add_argument('--timeout', '-t', type=float,
        default=None, help='socket timeout in seconds')
    add_timerange_args(parser)
    add_render_args(parser, verbose=True)

@templated('blacklist/incidentlist')
def run(client, args, kwargs):
    if kwargs.get('six_hours'):
        kwargs['start'] = six_hours()
        del kwargs['six_hours']
    data = client.get_blacklist_incident_list(**kwargs)
    return data, kwargs
