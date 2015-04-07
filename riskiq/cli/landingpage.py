#!/usr/bin/env python

import sys
import json

from riskiq.api import Client
from riskiq.render import renderer
from riskiq.cli import util


def lp_get(client, md5_hash, whois=None, as_json=False):
    data = client.get_landing_page(md5_hash, whois=whois)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer({'landingPage': [data]}, 'landingpage/crawled'))

def lp_submit(client, url, as_json=False, **kwargs):
    data = client.submit_landing_page(url, **kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer({'landingPage': [data]}, 'landingpage/crawled'))

def lp_crawled(client, as_json=None, **kwargs):
    data = client.get_landing_page_crawled(**kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/crawled'))

def lp_flagged(client, as_json=None, **kwargs):
    data = client.get_landing_page_flagged(**kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/crawled'))

def lp_submit_bulk(client, urls, as_json=False, **kwargs):
    entries = []
    for url in urls:
        entries += [{'url': url}]
    for entry in entries:
        entry.update(kwargs)
    data = client.submit_landing_page_bulk(entries)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/bulk'))

def lp_binary(client, as_json=False, **kwargs):
    data = client.get_landing_page_malicious_binary(**kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/crawled'))

def lp_projects(client, as_json=False):
    data = client.get_landing_page_projects()
    if as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'landingpage/projects'))

def main():
    import argparse
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    get_parser = subs.add_parser('get',
        help='Retrieve a single landingpage by MD5 hash')
    get_parser.add_argument('md5_hashes', nargs='+')
    get_parser.add_argument('--whois', '-w', action='store_true',
        help='whether to include whois information')
    get_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")

    submit_parser = subs.add_parser('submit',
        help='Submit at least one or many landing pages.')
    submit_parser.add_argument('urls', nargs='+')
    submit_parser.add_argument('--project', '-p',
        help='Project name to submit to')
    submit_parser.add_argument('--keyword', '-k',
        help='Optional Keyword')
    submit_parser.add_argument('--md5', '-m',
        help='Optional MD5 representing the canonical ID')
    submit_parser.add_argument('--pingback-url', '-P',
        help='Optional URL to be GET requested upon completion of analysis')
    submit_parser.add_argument('--fields', '-f', nargs='*',
        help='Optional list of custom fields eg -f foo=bar alpha=beta')
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

    binary_parser = subs.add_parser('binary',
        help='List landing pages with malicious binary incidents. '
            'A malicious binary is any non-text file that is suspected of '
            'containing malware or exploit code. A landing page is linked to '
            'any such binary that is embedded or easily reachable from it.'
    )
    binary_parser.add_argument('--whois', '-w', action='store_true',
        help='whether to include whois information')
    binary_parser.add_argument('--days', '-d', default=1, type=int,
        help='days to query')
    binary_parser.add_argument('--start', '-s', default=None,
        help='start datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    binary_parser.add_argument('--end', '-e', default=None,
        help='end datetime in yyyy-mm-dd HH:MM:SS format, or "today HH:MM:SS"')
    binary_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")

    pjs_parser = subs.add_parser('projects',
        help='List all projects that landing pages may be submitted to.')
    pjs_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")

    args = parser.parse_args()
    client = Client.from_config()

    kwargs = {'as_json': args.as_json}

    if hasattr(args, 'whois'):
        kwargs['whois'] = args.whois
    if hasattr(args, 'days'):
        kwargs['days'] = args.days
        kwargs['start'] = args.start
        kwargs['end'] = args.end
    if args.cmd == 'get':
        md5_hashes = util.stdin(args.md5_hashes)
        for md5_hash in md5_hashes:
            lp_get(client, md5_hash, **kwargs)
    elif args.cmd == 'submit':
        urls = util.stdin(args.urls)
        kwargs.update({
            'keyword': args.keyword,
            'md5_hash': args.md5,
            'pingback_url': args.pingback_url,
            'project_name': args.project,
        })
        if args.fields:
            kwargs.update({'fields': dict([f.split('=') for f in args.fields])})
        if len(urls) == 1:
            lp_submit(client, urls[0], **kwargs)
        else:
            lp_submit_bulk(client, urls, **kwargs)
    elif args.cmd == 'crawled':
        lp_crawled(client, **kwargs)
    elif args.cmd == 'flagged':
        lp_flagged(client, **kwargs)
    elif args.cmd == 'binary':
        lp_binary(client, **kwargs)
    elif args.cmd == 'projects':
        lp_projects(client, **kwargs)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
