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
    parser.add_argument('--start-index', '--si', type=int,
        help='start index, for pagination (default 0)')
    parser.add_argument('--max-results', '--mr', type=int,
        help='max results to return (default 10)')
    parser.add_argument('--auto', '-A', action='store_true',
        help='automatically fetch all results')
    add_render_args(parser)

@templated('blacklist/incident', yielding=True)
def run(client, args, kwargs):
    urls = stdin(args.urls)
    blkwargs = {}
    for url_param in ('start_index', 'max_results'):
        if getattr(args, url_param) is not None:
            blkwargs[url_param] = getattr(args, url_param)
    if args.auto:
        for url in urls:
            chunk_size = args.max_results or 1000
            chunk_i = args.start_index or 0
            data_ct = 0
            data = {'startIndex': 0, 'incident': []}
            while True:
                data_i = client.get_blacklist_incident(url, start_index=chunk_i,
                    max_results=chunk_size)
                data['incident'] += data_i['incident']
                size_data = len(data_i['incident'])
                data_ct += size_data
                chunk_i += size_data
                if data_ct >= data_i['totalResults']:
                    break
            data['totalResults'] = data_i['totalResults']
            yield data, kwargs
    else:
        for url in urls:
            data = client.get_blacklist_incident(url, **blkwargs)
            yield data, kwargs
