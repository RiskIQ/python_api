#!/usr/bin/env python
from riskiq.api import Client
from riskiq.output import PassiveDNS
from optparse import OptionParser
import re
import sys
IP_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.([0-9]{1,3}|\*|[0-9]{1,3}/[0-9]{1,2})$')


def main():
    parser = OptionParser()
    parser.add_option('-q', '--query', dest='query', action="store_true", default=False, help="Query Domain Name")
    parser.add_option('-d', '--data', dest='rdata', action="store_true", default=False, help="Response Data")
    parser.add_option('-i', '--ip', dest='rdata_ip', action="store_true", default=False, help="Response Data(IP)")
    parser.add_option('-t', '--rrtype', dest='rrtype', default=None, help="Record Type")
    parser.add_option('-j', '--json', dest='json', action="store_true", default=False, help="Output as JSON")
    options, args = parser.parse_args()
    if not args:
        parser.print_help()
        sys.exit(-1)
    client = Client.from_config()

    qtype = None
    if options.query:
        qtype = 'query'
    if options.rdata:
        qtype = 'data'
    if options.rdata_ip:
        qtype = 'ip'
    results = []
    for arg in args:
        if not qtype:
            if IP_REGEX.match(arg):
                qtype = 'ip'
            else:
                qtype = 'query'
        if qtype == 'data':
            results.append(client.get_dns_data_by_data(arg, rrtype=options.rrtype))
        if qtype == 'ip':
            results.append(client.get_dns_data_by_ip(arg, rrtype=options.rrtype))
        if qtype == 'query':
            results.append(client.get_dns_data_by_name(arg, rrtype=options.rrtype))
    results = PassiveDNS(results)
    if options.json:
        print(results.json)
        sys.exit(0)
    print(results.text)
    sys.exit(0)

