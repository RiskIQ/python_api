#!/usr/bin/env python
''' riskiq.cli.blacklist.incident
'''
import sys
from riskiq.cli.util import templated, stdin
from riskiq.cli.parser import add_timerange_args, add_render_args

CHUNK_SIZE = 200
START_INDEX_LIMIT = 10000
MAX_RESULTS_LIMIT = 1000

def add_parser(subs):
    parser = subs.add_parser('incident', help='query blacklist incident data '
        'by given URL/host/domain')
    parser.add_argument('urls', nargs='+', metavar='URL',
        help='URL/host/domain for which to query')
    parser.add_argument('--start-index', '--si', type=int,
        help='start index, for pagination (maximum of {}, server limit)'.format(
            START_INDEX_LIMIT))
    parser.add_argument('--max-results', '--mr', type=int,
        help='max results to return (default 10 if --start-index given, '
            'and maximum of {}, server limit)'.format(MAX_RESULTS_LIMIT))
    add_render_args(parser, verbose=True)

@templated('blacklist/incident', yielding=True, 
            sortkey='incident.date')
def run(client, args, kwargs):
    urls = stdin(args.urls)
    if args.start_index is None and args.max_results is None:
        for url in urls:
            chunk_i, data_ct = 0, 0
            data = {}
            incidents = []
            while True:
                data_i = client.get_blacklist_incident(url, start_index=chunk_i,
                    max_results=CHUNK_SIZE)
                data.update(data_i)
                incidents += data_i['incident']
                size_data = len(data_i['incident'])
                data_ct += size_data
                chunk_i += size_data
                if data_ct >= data_i['totalResults']:
                    break
                if chunk_i > START_INDEX_LIMIT:
                    break
            if not incidents:
                continue
            data['incident'] = incidents
            yield {url: data}, kwargs
    else:
        blkwargs = {}
        if args.start_index is not None and args.start_index > START_INDEX_LIMIT:
            sys.stderr.write('Capping start index to {}\n'.format(START_INDEX_LIMIT))
            args.start_index = START_INDEX_LIMIT
        if args.max_results is not None and args.max_results > MAX_RESULTS_LIMIT:
            sys.stderr.write('Capping max results to {}\n'.format(MAX_RESULTS_LIMIT))
            args.max_results = MAX_RESULTS_LIMIT
        for url_param in ('start_index', 'max_results'):
            if getattr(args, url_param) is not None:
                blkwargs[url_param] = getattr(args, url_param)
        for url in urls:
            data = client.get_blacklist_incident(url, **blkwargs)
            yield {url: data}, kwargs
