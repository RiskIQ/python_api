#!/usr/bin/env python

import sys
import json

from riskiq.api import Client
from riskiq.config import Config
from riskiq.render import renderer

def lp_get(client, md5_hash, whois=None, as_json=False):
    data = client.get_landing_page(md5_hash, whois=whois)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer({'landingPage': [data]}, 'landingpage/crawled'))

def lp_submit(client, url, project=None, as_json=False):
    data = client.submit_landing_page(url, project_name=project)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer({'landingPage': [data]}, 'landingpage/crawled'))

def lp_crawled(client,
    whois=None, as_json=None, days=None, start=None, end=None):
    data = client.get_landing_page_crawled(
        whois=whois, days=days, start=start, end=end
    )
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/crawled'))

def lp_flagged(client,
    whois=None, as_json=None, days=None, start=None, end=None):
    data = client.get_landing_page_flagged(
        whois=whois, days=days, start=start, end=end
    )
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/crawled'))

"""
date options boilerplate:
get_parser.add_argument('--days', '-d', default=1, type=int,
    help='days to query')
get_parser.add_argument('--start', '-s', default=None,
    help='start datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
get_parser.add_argument('--end', '-e', default=None,
    help='end datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
"""

def main():
    import argparse
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    get_parser = subs.add_parser('get',
        help='Retrieve a single landingpage by md5 hash')
    get_parser.add_argument('md5')
    get_parser.add_argument('--whois', '-w', action='store_true',
        help='whether to include whois information')
    get_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")

    submit_parser = subs.add_parser('submit',
        help='Submit a single landing page.')
    submit_parser.add_argument('url')
    submit_parser.add_argument('--project', '-p',
        help='Project name to submit to')
    submit_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")
    
    crawled_parser = subs.add_parser('crawled',
        help='List landing pages by crawl date - maximum of 100')
    crawled_parser.add_argument('--whois', '-w', action='store_true',
        help='whether to include whois information')
    crawled_parser.add_argument('--days', '-d', default=None, type=int,
        help='days to query')
    crawled_parser.add_argument('--start', '-s', default=None,
        help='start datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    crawled_parser.add_argument('--end', '-e', default=None,
        help='end datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    crawled_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")

    flagged_parser = subs.add_parser('flagged',
        help='List landing pages by known profile creation date - '
            'maximum of 100')
    flagged_parser.add_argument('--whois', '-w', action='store_true',
        help='whether to include whois information')
    flagged_parser.add_argument('--days', '-d', default=None, type=int,
        help='days to query')
    flagged_parser.add_argument('--start', '-s', default=None,
        help='start datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    flagged_parser.add_argument('--end', '-e', default=None,
        help='end datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    flagged_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")

    args = parser.parse_args()
    config = Config()
    client = Client(
        token=config.get('api_token'), key=config.get('api_private_key'),
        server=config.get('api_server'), version=config.get('api_version'),
    )

    kwargs = {'as_json': args.as_json}
    if hasattr(args, 'whois'):
        kwargs['whois'] = args.whois
    if hasattr(args, 'days'):
        kwargs['days'] = args.days
        kwargs['start'] = args.start
        kwargs['end'] = args.end
    if args.cmd == 'get':
        lp_get(client, args.md5, **kwargs)
    elif args.cmd == 'submit':
        lp_submit(client, args.url, project=args.project, **kwargs)
    elif args.cmd == 'crawled':
        lp_crawled(client, **kwargs)
    elif args.cmd == 'flagged':
        lp_flagged(client, **kwargs)

if __name__ == '__main__':
    main()
