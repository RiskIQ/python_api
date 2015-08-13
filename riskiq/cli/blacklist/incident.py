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
    parser.add_argument('--start-index', type=int,
        help='start index, for pagination (default 0)')
    parser.add_argument('--max-results', type=int,
        help='max results to return (default 10)')
    add_render_args(parser)

@templated('blacklist/incident', yielding=True)
def run(client, args, kwargs):
    urls = stdin(args.urls)
    blkwargs = {}
    for url_param in ('start_index', 'max_results'):
        if getattr(args, url_param) is not None:
            blkwargs[url_param] = getattr(args, url_param)
    for url in urls:
        data = client.get_blacklist_incident(url, **blkwargs)
        yield data, kwargs
