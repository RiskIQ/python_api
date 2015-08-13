#!/usr/bin/env python
''' riskiq.cli.blacklist.bl_list
'''
from riskiq.cli.util import templated, six_hours
from riskiq.cli.parser import add_timerange_args, add_render_args
from riskiq.cli.blacklist import FILTERS

def add_parser(subs):
    parser = subs.add_parser('list', help = 'query blacklisted resources')
    parser.add_argument('--filter', '-f', default=None,
        help='filter to one of "blackhole", "sakura" or "exploitKit"')
    add_timerange_args(parser)
    add_render_args(parser)

def main(client, args, kwargs):
    data = client.get_blacklist_incident_list(**kwargs)
    return data, kwargs

@templated('blacklist/malware')
def run(client, args, kwargs):
    if kwargs.get('six_hours'):
        kwargs['start'] = six_hours()
        del kwargs['six_hours']
    blacklist_filter = kwargs['filter']
    del kwargs['filter']
    if blacklist_filter not in (None, ) + FILTERS:
        raise ValueError('Invalid filter. Must be one of %s' % str(FILTERS))
    data = client.get_blacklist_list(blacklist_filter=blacklist_filter,
        **kwargs)
    return data, kwargs
