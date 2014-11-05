import sys
import json
from argparse import ArgumentParser

from riskiq.api import Client
from riskiq.config import Config
from riskiq.cli import util


def bin_list(client, as_json=False, **kwargs):
    ''' List suspicious binaries within a specific date range '''
    data = client.get_binary_list(**kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    else:
        raise NotImplementedError('only prints as json currently')


def bin_download(client, md5hash, as_json=False):
    ''' Download a suspicious binary from its md5 hash '''
    data = client.get_binary_data(md5hash)
    if as_json:
        print(json.dumps(data, indent=4))
    else:
        raise NotImplementedError('only prints as json currently')


def main():
    parser = ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    list_parser = subs.add_parser('list', help='list binaries in date range')
    list_parser.add_argument('--days', '-d', default=1, type=int,
        help='days to query')
    list_parser.add_argument('--start', '-s', default=None,
        help='start datetime in yyyy-mm-dd HH:MM:SS format')
    list_parser.add_argument('--end', '-e', default=None,
        help='end datetime in yyyy-mm-dd HH:MM:SS format')
    list_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")

    download_parser = subs.add_parser('download',
        help='download from md5 hash, or hashes')
    download_parser.add_argument('md5hash', nargs='+')
    download_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")

    args = parser.parse_args()
    kwargs = {'as_json': args.as_json}
    if hasattr(args, 'days'):
        kwargs['days'] = args.days
        kwargs['start'] = args.start
        kwargs['end'] = args.end

    config = Config()
    client = Client(token=config.get('api_token'), key=config.get('api_private_key'),
                    server=config.get('api_server'), version=config.get('api_version'))
    
    if args.cmd == 'list':
        bin_list(client, **kwargs)
    elif args.cmd == 'download':
        hashes = util.stdin(args.md5hash)
        for md5hash in hashes:
            bin_download(client, md5hash, **kwargs)

if __name__ == '__main__':
    main()
