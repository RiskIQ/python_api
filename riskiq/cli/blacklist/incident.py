#!/usr/bin/env python
''' riskiq.cli.blacklist.incident
'''
from riskiq.cli.util import templated, stdin
from riskiq.cli.parser import add_timerange_args, add_render_args

def add_parser(subs):
    parser = subs.add_parser('incident', help='query blacklist incident data '
        'by given URL/host/domain')
    parser.add_argument('urls', nargs='+', metavar='URL',
        help='URL/host/domain for which to query')
    add_render_args(parser)

@templated('blacklist/incident', yielding=True)
def run(client, args, kwargs):
    urls = stdin(args.urls)
    for url in urls:
        data = client.get_blacklist_incident(url)
        yield data, kwargs
