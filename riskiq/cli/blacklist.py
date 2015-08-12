import sys
import json
from argparse import ArgumentParser

from riskiq.api import Client
from riskiq.render import renderer
from riskiq.cli import util

try:
    from riskiq import blacklist_stix
    NO_STIX = False
except ImportError:
    NO_STIX = True

FILTERS = ('blackhole', 'sakura', 'exploitKit')
CONFIDENCES = ('H', 'M', 'L')

def dump_stix(data, path):
    if NO_STIX:
        raise RuntimeError('Please install riskiq[stix]')
    data = blacklist_stix.load_bldata(data)
    output_xml = blacklist_stix.stix_xml(data)
    blacklist_stix.dump_xml(path, output_xml)
    print('Dumped STIX XML to {}'.format(path))

def bl_lookup(client, url, stix=None, oneline=False, as_json=False):
    data = client.get_blacklist_lookup(url)
    if stix:
        dump_stix(data, stix)
    elif as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'blacklist/lookup', oneline=oneline))

def bl_incident(client, url, stix=None, verbose=False, oneline=False,
    as_json=False):
    data = client.get_blacklist_incident(url)
    if stix:
        dump_stix(data, stix)
    elif as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'blacklist/incident', verbose=verbose,
            oneline=oneline))

def bl_incidentlist(client, stix=None, oneline=False, as_json=False,
    **kwargs):
    if kwargs.get('six_hours'):
        from datetime import datetime, timedelta
        td = (datetime.now() - timedelta(hours=6)).strftime('%Y-%m-%d %H:%M:%S')
        kwargs['start'] = td
    del kwargs['six_hours']
    data = client.get_blacklist_incident_list(**kwargs)
    if stix:
        dump_stix(data, stix)
    elif as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'blacklist/incident', oneline=oneline))

def bl_list(client, bl_filter=None, stix=None, oneline=False, as_json=False,
    **kwargs):
    if bl_filter not in (None, ) + FILTERS:
        raise ValueError('Invalid filter. Must be one of %s' % str(FILTERS))
    data = client.get_blacklist_list(blacklist_filter=bl_filter, **kwargs)
    if stix:
        dump_stix(data, stix)
    elif as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'blacklist/malware', oneline=oneline))

def bl_malware(client, stix=None, oneline=False, as_json=False,
    bl_filter=None, confidence=None, **kwargs):
    if bl_filter not in (None, ) + FILTERS:
        raise ValueError('Invalid filter.\nMust be one of %s' % str(FILTERS))
    if confidence not in (None, ) + CONFIDENCES:
        raise ValueError('Invalid confidence.\n'
            'Must be one of %s' % str(CONFIDENCES))
    data = client.get_blacklist_malware(blacklist_filter=bl_filter,
        confidence=confidence, **kwargs)
    if stix:
        dump_stix(data, stix)
    elif as_json:
        print(json.dumps(data, indent=4))
    elif data:
        print(renderer(data, 'blacklist/malware', oneline=oneline))

def main():
    parser = ArgumentParser()
    parser.add_argument('--dump-requests', action='store_true')
    parser.add_argument('--stix',
        help='output results to STIX file (requires riskiq[stix] package)')
    subs = parser.add_subparsers(dest='cmd')
    
    lookup_parser = subs.add_parser('lookup', help='look up URL/host/domain on '
        'RiskIQ Global Blacklist (GBL)')
    lookup_parser.add_argument('urls', nargs='+', metavar='URL', help='URL/host/domain for which to query')
    lookup_parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    #lookup_parser.add_argument('-s', '--short', action="store_true",
    #    help="output in short format (print matching input indicator only)")
    lookup_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="output raw JSON response")

    incident_parser = subs.add_parser('incident', help='query blacklist incident data '
        'by given URL/host/domain')
    incident_parser.add_argument('urls', nargs='+', metavar='URL', help='URL/host/domain for which to query')
    incident_parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    #incident_parser.add_argument('-s', '--short', action="store_true",
    #    help="output in short format (print matching input indicator only)")
    incident_parser.add_argument('-v', '--verbose', action="store_true",
        help="output additional incident data (used with standard long output)")
    incident_parser.add_argument('-j', '--json', action="store_true", dest='as_json',
        help="output raw JSON response")

    incident_list_parser = subs.add_parser('incidentlist',
        help='query blacklist incidents within given timeframe')
    incident_list_parser.add_argument('--all-workspace-crawls', '-a',
        action='store_true', help='filter crawls to those on workspace')
    incident_list_parser.add_argument('--days', '-d', default=1, type=int,
        help='number of days to query')
    incident_list_parser.add_argument('--six-hours', '-6', action='store_true',
        help='request last 6 hours of data')
    incident_list_parser.add_argument('--start', '-s', default=None,
        help='start datetime in YYYY-MM-DD HH:MM:SS format')
    incident_list_parser.add_argument('--end', '-e', default=None,
        help='end datetime in YYYY-MM-DD HH:MM:SS format')
    incident_list_parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    incident_list_parser.add_argument('--timeout', '-t', type=float,
        default=None, help='socket timeout in seconds')
    #incident_list_parser.add_argument('-s', '--short', action="store_true",
    #    help="output in short format (print matching input indicator only)")
    incident_list_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="output raw JSON response")

    list_parser = subs.add_parser('list', help = 'query blacklisted resources')
    list_parser.add_argument('--filter', '-f', default=None,
        help='filter to one of "blackhole", "sakura" or "exploitKit"')
    list_parser.add_argument('--days', '-d', default=1, type=int,
        help='number of days to query')
    list_parser.add_argument('--start', '-s', default=None,
        help='start datetime in YYYY-MM-DD HH:MM:SS format')
    list_parser.add_argument('--end', '-e', default=None,
        help='end datetime in YYYY-MM-DD HH:MM:SS format')
    list_parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    #list_parser.add_argument('-s', '--short', action="store_true",
    #    help="output in short format (print matching input indicator only)")
    list_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="output raw JSON response")

    malware_parser = subs.add_parser('malware',
        help='query RiskIQ suspicious binary feed for all samples stored within a '
            'given period')
    malware_parser.add_argument('--filter', '-f', default=None,
        help='filter to one of "blackhole", "sakura" or "exploitKit"')
    malware_parser.add_argument('--confidence', '-c', choices=['H', 'M', 'L'],
        default=None, help='restrict results to malicious probability of '
        '[H]igh, [M]edium, or [L]ow')
    malware_parser.add_argument('--days', '-d', default=1, type=int,
        help='number of days to query')
    malware_parser.add_argument('--start', '-s', default=None,
        help='start datetime in YYYY-MM-DD HH:MM:SS format, or "today HH:MM:SS"')
    malware_parser.add_argument('--end', '-e', default=None,
        help='end datetime in YYYY-MM-DD HH:MM:SS format, or "today HH:MM:SS"')
    malware_parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    #malware_parser.add_argument('-s', '--short', action="store_true",
    #    help="output in short format (print matching input indicator only)")
    malware_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="output raw JSON response")

    args = parser.parse_args()
    client = Client.from_config()

    if args.dump_requests:
        client._dump_requests()

    kwargs = {'as_json': args.as_json, 'oneline': args.oneline, 
        'stix': args.stix}
    if hasattr(args, 'days'):
        kwargs['days'] = args.days
        kwargs['start'] = args.start
        kwargs['end'] = args.end
    for attr in ('timeout', 'six_hours'):
        if hasattr(args, attr):
            kwargs[attr] = getattr(args, attr)
    if args.cmd == 'lookup':
        urls = util.stdin(args.urls)
        for url in urls:
            bl_lookup(client, url, **kwargs)
    elif args.cmd == 'incidentlist':
        bl_incidentlist(client, all_workspace_crawls=args.all_workspace_crawls,
            **kwargs)
    elif args.cmd == 'incident':
        kwargs['verbose'] = args.verbose
        urls = util.stdin(args.urls)
        for url in urls:
            bl_incident(client, url, **kwargs)
    elif args.cmd == 'list':
        try:
            bl_list(client, bl_filter=args.filter, **kwargs)
        except ValueError as e:
            parser.print_usage()
            print(str(e))
            sys.exit(1)
    elif args.cmd == 'malware':
        try:
            bl_malware(client, bl_filter=args.filter,
                confidence=args.confidence, **kwargs)
        except ValueError as e:
            parser.print_usage()
            print(str(e))
            sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
