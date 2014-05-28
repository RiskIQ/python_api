from libriskiq.config import Config
from libriskiq.output import GenericOutput
from optparse import OptionParser
import sys

def main():
    parser = OptionParser()
    parser.add_option('-k', '--key', dest='key', default='', help="API Key")
    parser.add_option('-s', '--secret', dest='secret', default='', help="API Secret")
    options, args = parser.parse_args()
    config_options = {}
    if options.key:
        config_options['api_key'] = options.key
    if options.secret:
        config_options['api_secret'] = options.secret
    config = Config(**config_options)
    print parser.print_help()
    print "\n\nCurrent Configuration:\n"
    for k, v in sorted(config.config.items()):
        print "%15s: %s" % (k, v)
    sys.exit(0)

if __name__ == '__main__':
    main()
