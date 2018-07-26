#!/usr/bin/env python

import re
import sys
import json

from riskiq.api import Client
from riskiq.render import renderer
from riskiq.cli import util

IP_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.([0-9]{1,3}|\*|[0-9]{1,3}/[0-9]{1,2})$')


def ip_hostname(addr):
    match = IP_REGEX.match(addr)
    if match:
        ip = addr
        hostname = None
    else:
        ip = None
        hostname = addr
    return ip, hostname

def get_data(client, cmd, rrtype=None, hostname=None, ip=None):
    data = None
    if cmd == 'name':
        if ip is not None:
            data = client.get_dns_ptr_by_ip(ip, rrtype=rrtype, maxresults=500)
        elif hostname is not None:
            data = client.get_dns_data_by_name(hostname, rrtype=rrtype)
        else:
            raise ValueError('No IP or hostname')
    elif cmd == 'data':
        if ip is not None:
            data = client.get_dns_data_by_ip(ip, rrtype=rrtype, maxresults=500)
        elif hostname is not None:
            data = client.get_dns_data_by_data(hostname, rrtype=rrtype)
        else:
            raise ValueError('No IP or hostname')
    else:
        raise ValueError('Invalid command')
    return data

def main():
    import argparse
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    name_p = subs.add_parser('name')
    name_p.add_argument('addrs', nargs='+', help='Hostname or IP addresses')
    name_p.add_argument('--rrtype', '-t', default=None)
    name_p.add_argument('--json', '-j', action="store_true",
        help="Output as JSON")
    name_p.add_argument('--short', '-s', action="store_true",
        help="Output newline-separated data only")
    name_p.add_argument('--text', '-T', action="store_true",
        help="Output full human readable text")
    name_p.add_argument('--verbose', '-v', action="store_true",
        help="Output verbose records with first/lastseen times and observed count")

    data_p = subs.add_parser('data')
    data_p.add_argument('addrs', nargs='+', help='Hostname or IP addresses')
    data_p.add_argument('--rrtype', '-t', default=None)
    data_p.add_argument('--json', '-j', action="store_true",
        help="Output as JSON")
    data_p.add_argument('--short', '-s', action="store_true",
        help="Output newline-separated name only")
    data_p.add_argument('--text', '-T', action="store_true",
        help="Output full human readable text")
    data_p.add_argument('--verbose', '-v', action="store_true",
        help="Output verbose records with first/lastseen times and observed count")

    args = parser.parse_args()

    addrs = util.stdin(args.addrs)
    for addr in addrs:
        ip, hostname = ip_hostname(addr)

        client = Client.from_config()
        try:
            data = get_data(client, args.cmd, rrtype=args.rrtype,
                hostname=hostname, ip=ip)
        except ValueError as e:
            parser.print_usage()
            sys.stderr.write('{}\n'.format(str(e)))
            sys.exit(1)

        if args.json:
            print(json.dumps(data, indent=4))
        elif args.short and args.cmd == 'data':
            print(renderer(data, 'dns/dns_data'))
        elif args.short and args.cmd == 'name':
            print(renderer(data, 'dns/dns_name'))
        elif args.text:
            print(renderer(data, 'dns/dns'))
        elif data:
            print(renderer(data, 'dns/dns_oneline', verbose=args.verbose))
