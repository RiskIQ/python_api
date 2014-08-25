import sys
from optparse import OptionParser
from riskiq.api import Client
from riskiq.config import Config
from riskiq.output import BlacklistIncident, BlacklistEntry

def main():
    # TODO: Implement date range options
    usage = "%prog [options] INDICATOR [...]"
    parser = OptionParser(usage)
    # parser.add_option('-g', '--global-incidents', dest='global_incidents', action='store_true', default=False,
    #                   help='Global Incident List')
    # parser.add_option('-i', '--incidents', dest='incidents', action='store_true', default=False,
    #                   help='Workspace Incident List')
    # parser.add_option('-m', '--malware', dest='malware', action='store_true', default=False, help='Malware Incidents')
    # parser.add_option('-M', '--malware-confidence', dest='malware_confidence', action='store', default=None,
    #                   help='Malware Confidence (L, M, H)')
    parser.add_option('-j', '--json', dest='json', action="store_true", default=False, help="Output as JSON")
    parser.add_option('-l', '--oneline', dest='oneline', action="store_true", default=False, help="Output in one single line (print blacklist match info one line per entry)")
    parser.add_option('-s', '--short', dest='short', action="store_true", default=False, help="Output in short format (print matching input indicator only)")
    options, args = parser.parse_args()
    config = Config()
    client = Client(token=config.get('api_token'), key=config.get('api_private_key'),
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
    elif options.short:
        print results.short
    elif options.oneline:
        print results.oneline
    else:
        print results.text

if __name__ == '__main__':
    main()
