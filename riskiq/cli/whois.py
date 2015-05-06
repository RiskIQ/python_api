#!/usr/bin/env python
import os
import sys
import json

from riskiq.api import Client
from riskiq.render import renderer

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', '-d')
    parser.add_argument('--email', '-e')
    parser.add_argument('--name-server', '-n')
    parser.add_argument('--max-results', '-m', type=int, default=100)
    parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="Output as JSON")
    args = parser.parse_args()
    client = Client.from_config()
    results = client.post_whois(domain=args.domain, email=args.email, 
        name_server=args.name_server, max_results=args.max_results)
    if args.as_json:
        print(json.dumps(results, indent=4))
    else:
        print(renderer(results, 'whois/whois'))

if __name__ == '__main__':
    main()
