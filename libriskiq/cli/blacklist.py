#!/usr/bin/env python
from libriskiq.api import Client
from libriskiq.config import Config
from libriskiq.output import BlacklistIncident, BlacklistEntry
from optparse import OptionParser
import sys


def main():
    # Todo: Date options
    parser = OptionParser()
    # parser.add_option('-g', '--global-incidents', dest='global_incidents', action='store_true', default=False,
    #                   help='Global Incident List')
    # parser.add_option('-i', '--incidents', dest='incidents', action='store_true', default=False,
    #                   help='Workspace Incident List')
    # parser.add_option('-m', '--malware', dest='malware', action='store_true', default=False, help='Malware Incidents')
    # parser.add_option('-M', '--malware-confidence', dest='malware_confidence', action='store', default=None,
    #                   help='Malware Confidence (L, M, H)')
    parser.add_option('-j', '--json', dest='json', action="store_true", default=False, help="Output as JSON")
    options, args = parser.parse_args()
    config = Config()
    client = Client(key=config.get('api_key'), secret=config.get('api_secret'),
                    server=config.get('api_server'), version=config.get('api_version'))
    # TODO: Global Blacklist Downloads
    if not args:
        parser.print_help()
        sys.exit(-1)
    results = []

    for arg in args:
        result = client.get_blacklist_lookup(arg)
        if result:
            results.append(result)
    results = BlacklistEntry(results)
    if options.json:
        print results.json
        sys.exit(0)
    print results.text
    sys.exit(0)

if __name__ == '__main__':
    main()