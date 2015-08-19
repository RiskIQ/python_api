#!/usr/bin/env python
''' riskiq.cli.blacklist.lookup
'''
from riskiq.cli.util import templated, stdin
from riskiq.cli.parser import add_timerange_args, add_render_args

def add_parser(subs):
    parser = subs.add_parser('lookup', help='look up URL/host/domain on '
        'RiskIQ Global Blacklist (GBL)')
    parser.add_argument('urls', nargs='+', metavar='URL', help='URL/host/domain for which to query')
    add_render_args(parser)

@templated('blacklist/lookup', yielding=True)
def run(client, args, kwargs):
    urls = stdin(args.urls)
    for url in urls:
        data = client.get_blacklist_lookup(url)
        if not data:
            continue
        yield {url: data}, kwargs
