from riskiq.config import Config
from riskiq.output import GenericOutput
from optparse import OptionParser
import sys


def main():
    usage = """%prog -t TOKEN -k KEY\n       %prog -p"""
    parser = OptionParser(usage)
    parser.add_option('-t', '--token', dest='token', default='', help='API token')
    parser.add_option('-k', '--key', dest='key', default='', help='API private key')
    parser.add_option('-p', '--print', action='store_true', dest='show_config',
                      default=False, help='Show current API configuration')
    options, args = parser.parse_args()
    if options.show_config:
        config = Config()
        show_config(config)
        sys.exit(0)
    config_options = {}
    if not options.token or not options.key:
        parser.error("provide API token and secret key to configure client")
    config_options['api_token'] = options.token
    config_options['api_private_key'] = options.key

    config = Config(**config_options)
    show_config(config)
    sys.exit(0)


def show_config(config):
    print "\nCurrent Configuration:\n"
    for k, v in sorted(config.config.items()):
        print "%15s: %s" % (k, v)

if __name__ == '__main__':
    main()

