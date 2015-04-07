import sys
import os
import json
from argparse import ArgumentParser

from riskiq.api import Client
from riskiq.cli import util


def bin_list(client, as_json=False, **kwargs):
    ''' List suspicious binaries within a specific date range '''
    data = client.get_binary_list(**kwargs)
    if as_json:
        print(json.dumps(data, indent=4))
    else:
        for binary in data['binaryIncident']:
            print(binary['md5'])


def bin_download(client, md5hash, as_json=False, output=None, output_dir=None):
    ''' Download a suspicious binary from its MD5 hash '''
    data = client.get_binary_data(md5hash)
    if as_json:
        print(json.dumps(data, indent=4))
    if output is not None:
        with open(output, 'w') as f:
            f.write(data['data'].decode('base64'))
    elif output_dir is not None:
        path = os.path.join(output_dir, md5hash + '.bin')
        with open(path, 'w') as f:
            f.write(data['data'].decode('base64'))
    else:
        print(data['data'].decode('base64'))

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
        help='download from MD5 hash, or hashes')
    download_parser.add_argument('md5hash', nargs='+')
    download_parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="Output as JSON")
    download_parser.add_argument('-o', '--output',
        help='path to output file to')
    download_parser.add_argument('-d', '--output-dir',
        help='dir to dump $hash.bin to')

    args = parser.parse_args()
    kwargs = {'as_json': args.as_json}
    if hasattr(args, 'days'):
        kwargs['days'] = args.days
        kwargs['start'] = args.start
        kwargs['end'] = args.end

    client = Client.from_config()
    
    if args.cmd == 'list':
        bin_list(client, **kwargs)
    elif args.cmd == 'download':
        hashes = util.stdin(args.md5hash)
        for i, md5hash in enumerate(hashes):
            output = args.output
            if output and len(hashes) > 1:
                output = '%s.%d' % (args.output, i)
            bin_download(client, md5hash,
                output=output, output_dir=args.output_dir,
                **kwargs)

if __name__ == '__main__':
    try:
       main()
    except KeyboardInterrupt:
       pass
