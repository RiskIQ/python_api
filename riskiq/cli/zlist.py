#!/usr/bin/env python

import sys
import json

from riskiq.api import Client
from riskiq.render import renderer

def main():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")
    parser.add_argument('--days', '-d', default=1, type=int,
        help='days to query')
    parser.add_argument('--start', '-s', default=None,
        help='start datetime in "yyyy-mm-dd HH:MM:SS" format '
            '(or "today HH:MM:SS")')
    parser.add_argument('--end', '-e', default=None,
        help='end datetime in "yyyy-mm-dd HH:MM:SS" format '
            '(or "today HH:MM:SS")')
    args = parser.parse_args()

    client = Client.from_config()

    kwargs = {'as_json': args.as_json}
    kwargs['days'] = args.days
    kwargs['start'] = args.start
    kwargs['end'] = args.end
    
    data = client.get_zlist_urls(days=args.days, start=args.start,
        end=args.end)

    if args.as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'zlist/urls'))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
