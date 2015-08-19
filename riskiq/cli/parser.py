#!/usr/bin/env python
''' riskiq.cli.parser
Generic argparse added arguments
'''

def add_timerange_args(parser):
    parser.add_argument('--days', '-d', default=1, type=int,
        help='number of days to query')
    parser.add_argument('--six-hours', '-6', action='store_true',
        help='request last 6 hours of data')
    parser.add_argument('--start', '-s', default=None,
        help='start datetime in YYYY-MM-DD HH:MM:SS format')
    parser.add_argument('--end', '-e', default=None,
        help='end datetime in YYYY-MM-DD HH:MM:SS format')

def add_render_args(parser, verbose=False):
    parser.add_argument('-l', '--oneline', action="store_true",
        help="output one entry per line")
    parser.add_argument('-j', '--json', action="store_true",
        dest='as_json', help="output raw JSON response")
    parser.add_argument('-T', '--template',
        help='path to custom template')
    if verbose:
        parser.add_argument('-v', '--verbose', action="store_true",
            help="output additional incident data in default templates")
