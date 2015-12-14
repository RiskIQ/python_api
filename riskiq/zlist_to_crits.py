#!/usr/bin/env python
#
# Load a ZList JSON extract into CRITs as Indicators.
#
# Currently, CRITs documentation on Indicators in the authenticated API
# is lacking. Refer to the source code for a more complete picture:
#
# https://github.com/crits/crits/blob/master/crits/indicators/api.py

import re
import sys
import json
import os.path
import argparse
import urlparse
import ConfigParser
from datetime import datetime
import logging, logging.handlers

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


CONFIG_DEFAULTS = {
    'cert_verify': 'yes',
    'silence_insecure_warnings': 'no',
    'syslog_address': '/dev/log',
    'bucket_list_default': 'riq_zlist',
    'indicator_impact': 'unknown',
    'attack_type': 'Unknown',
    'add_domain': 'yes',
    'add_relationship': 'yes',
}

# Maps ZList score to CRITs confidence level. Score ranges are inclusive.
INDICATOR_CONFIDENCE = {
    (75,100): 'high',
    (50, 74): 'medium',
    (1, 49):  'low',
    (0, 0):   'benign',
}

# Maps ZList item match level to CRITs indicator type
MATCHLEVEL_TYPE = {
    'URL':    {'type': 'URI', 'threat_type': 'Malicious URL'},
    'PATH':   {'type': 'URI', 'threat_type': 'Malicious URL Chunk'},
    'HOST':   {'type': 'Domain', 'threat_type': 'Malicious Domain'},
    'DOMAIN': {'type': 'Domain', 'threat_type': 'Malicious Domain'},
}

# IPv4 address pattern (single /32)
IPV4_PATTERN = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
ZLIST_THREAT_TYPE = re.compile(r'^riq\.\S+\s+(?P<type>[0-9A-Z]+)\s+')


# Set up logging and logger object globally
logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s')
logging.captureWarnings(True)
logger = logging.getLogger(__name__)

class ZListIndicator(object):
   '''
   Representation of ZList item as a CRITs Indicator ready for API submission

   '''
   def __init__(self, config, item):
       self._item = item
       self._config = config
       self.source = config.get('indicators', 'source')
       self.add_domain = config.get('indicators', 'add_domain')
       self.add_relationship = config.get('indicators', 'add_relationship')
       self.attack_type = self._get_attack_type()
       self.bucket_list = self._get_bucket_list()
       self.indicator_confidence = self._get_indicator_confidence()
       self.indicator_impact = self._get_indicator_impact()
       self.threat_type = MATCHLEVEL_TYPE[self._item['maxMatchType']]['threat_type']
       # The call to _set_indicator_attributes() should come last to
       # override any previously set values with more specific values
       self._set_indicator_attributes()

   def _set_indicator_attributes(self):
       '''
       Set assorted indicator attributes.

       Several indicator attributes can be set conditionally and this
       method handles calculating them.
       '''
       url_netloc = self._extract_netloc()
       self.type = MATCHLEVEL_TYPE[self._item['maxMatchType']]['type']
       if is_ipv4(url_netloc):
           # Handle URLs where the host is an IP address
           if self.type == 'URI':
               self.value = self._item['url']
           else: 
               self.type = 'IPv4 Address'
               self.value = url_netloc
               self.threat_type = 'Malicious IP'
       else:
           # Host is not an IP address
           if self.type == 'Domain':
               self.value = url_netloc
           else:
               self.value = self._item['url']

   def _get_indicator_confidence(self):
       '''Set indicator confidence base on ZList score field'''
       for score, val in INDICATOR_CONFIDENCE.items():
           if self._item['score'] in range(score[0], score[1]+1):
               return val

   def _get_indicator_impact(self):
       '''
       Return CRITs indicator_impact value.

       Currently we don't track impact or severity scores per ZList item,
       so just return unknown (should be value in config file). In the
       future this could change in one of a few possible ways.
       '''
       return self._config.get('indicators', 'indicator_impact')

   def _extract_netloc(self):
       '''Extract hostname/IP address from ZList URL'''
       return urlparse.urlparse(self._item['url']).netloc

   def _get_attack_type(self):
       '''
       Return CRITs indicator attack_type value.

       Currently we don't have available Attack Types defined and easily
       parseable, so just return a static value (should be set in config).
       '''
       return self._config.get('indicators', 'attack_type')

   def _get_bucket_list(self):
       '''
       Return CRITs indicator bucket_list value.

       Bucket lists are assigned the global default as well as any ZList
       Taxonomy threat type value in the description, in lowercase.
       '''
       bucket_list = self._config.get('indicators', 'bucket_list_default').rstrip(',')
       bucket_list = bucket_list.split(',')
       desc = self._item['description']
       m = ZLIST_THREAT_TYPE.match(desc)
       if m:
           bucket_list.append(m.group('type'))
       bucket_list = ','.join(bucket_list)
       return bucket_list.lower()

   def as_dict(self):
       '''
       Return instance of indicator object as dictionary that omits
       attributes that start with an underscore
       '''
       return {name: val for name, val in vars(self).items()
               if not '_' in name[0]}

def extract_zlist_indicators(config, zlist_items):
   '''Extract and format appropriate indicator objects from ZList data'''
   for zlist_item in zlist_items:
       indicator = ZListIndicator(config, zlist_item)
       yield indicator

def add_indicator(config, indicator):
    '''Add indicator data to CRITs'''
    # Number of bytes of server response body to display in debug output later
    debug_bytes = 200
    indicators_url = config.get('crits', 'api_url').rstrip('/') + '/indicators/'
    username = config.get('crits', 'username')
    api_key = config.get('crits', 'api_key')
    cert_verify = config.getboolean('crits', 'cert_verify')
    logger.debug('indicator JSON: %s', json.dumps(indicator.as_dict()))
    # Slap credentials on and upload Indicator
    headers = {'Authorization': 'ApiKey {}:{}'.format(username, api_key)}
    logger.debug('sending POST request to CRITs API')
    start = datetime.now()
    r = requests.post(indicators_url, json=indicator.as_dict(),
                      headers=headers, verify=cert_verify)
    end = datetime.now()
    time_taken = (end - start).total_seconds()
    logger.debug('time taken to submit indicator: %fs', time_taken)
    logger.debug('response status from CRITs server: %s %s', r.status_code, r.reason)
    resp_body_msg = 'response body from CRITs server'
    if len(r.text) > debug_bytes:
        resp_body_msg += ' (truncated to {} bytes)'.format(debug_bytes)
    logger.debug(resp_body_msg + ': %s', r.text[:debug_bytes] or '<empty response>')

    # Raise any error status or continue and process response
    r.raise_for_status()
    server_response = r.json()

    # Return dictionary indicating status of submission (based on
    # return_code), time taken to receive API response, and message with
    # details from response.
    success = True if server_response.get('return_code') == 0 else False
    logger.debug('indicator submission %s', 'succeeded' if success else 'failure')
    return {'success': success, 'status': server_response['return_code'],
            'message': server_response.get('message'), 'time_taken': time_taken}

def is_ipv4(val):
    '''Check if the value is a valid IPv4 address'''
    if not re.match(IPV4_PATTERN, val):
        return False
    for octet in val.split('.'):
        if not 0 <= int(octet) <= 255:
            return False
    return True

def add_syslog_handler(syslog_address):
    '''Add syslog handler to global logging configuration'''
    logger.debug('enabling syslog output on %s', syslog_address)
    handler = logging.handlers.SysLogHandler(syslog_address)
    format = '{name}: [%(levelname)s] %(message)s'.format(
        name=os.path.basename(__file__))
    formatter = logging.Formatter(format)
    handler.formatter = formatter
    logger.addHandler(handler)

def main():
    parser = argparse.ArgumentParser(description='Load ZList JSON data into CRITs')
    parser.add_argument('file', type=argparse.FileType(), help='ZList JSON file to load')
    parser.add_argument('--config-file', '-c', type=argparse.FileType(),
                        default='/etc/zlist_crits.conf',
                        help='configuration file (default: %(default)s)')
    parser.add_argument('--log-level', '-l', choices=('error','warning','info','debug'),
                        default='warning',
                        help='logging verbosity level (default: %(default)s)')
    parser.add_argument('--syslog', '-S', action='store_true',
                        help='enable logging to syslog (default: %(default)s)')
    parser.add_argument('--silence-insecure-warnings', '-s', action='store_true',
                        help='suppress insecure connection warnings'
                             ' (appear when disabling cert checking; default: %(default)s)')
    args = parser.parse_args()

    # Set log level
    logger.setLevel(getattr(logging, args.log_level.upper()))

    # Load configuration 
    logger.debug('loading configuration from %s', args.config_file.name)
    config = ConfigParser.RawConfigParser(CONFIG_DEFAULTS)
    config.readfp(args.config_file)
    sections = config.sections()
    for s in sections:
        logger.debug('Configuration for section [%s]: %s', s, config.items(s))

    # Enable syslog if specified
    if args.syslog:
        syslog_address = config.get('main', 'syslog_address')
        add_syslog_handler(syslog_address)

    # Silence insecure request warnings if specified
    if args.silence_insecure_warnings or config.getboolean(
           'main', 'silence_insecure_warnings'):
       requests.packages.urllib3.disable_warnings(
           requests.packages.urllib3.exceptions.InsecureRequestWarning)

    # Extract ZList items and prepare data
    filepath = os.path.abspath(args.file.name)
    logger.info('reading ZList data from file %s', filepath)
    try:
        zlist_items = json.load(args.file)['items']
    except KeyError as e:
        logger.error('error parsing invalid input file format')
        logger.debug('requires valid ZList export JSON file (error in %s field)', e)
        sys.exit('Exiting')
    args.file.close()
    zlist_item_count = len(zlist_items)
    logger.info('extracted %d ZList item(s)', zlist_item_count)

    # Create indicators and send to CRITs. Config parsing errors can
    # show along the way so handle exception here.
    try:
        time_total = cnt_success = cnt_fail = 0
        for item in extract_zlist_indicators(config, zlist_items):
    # {'success' (bool), 'status' (return code, 0 = success)
    #  'message': (str, may be missing), 'time_taken': time_taken}
            result = add_indicator(config, item)
            time_total += result['time_taken']
            if result['success']:
                cnt_success += 1
            else:
                cnt_fail += 1
                logger.warning('issue submitting indicator %s: %s',
                               item.value, result.get('message', 'no details returned'))
    except ConfigParser.NoSectionError as e:
        errmsg = 'unable to read option from configuration: {}'.format(e)
        logger.error(errmsg)
        parser.error(errmsg)
    except KeyError as e:
        # Catching this early, likely due to error parsing data from input
        # file (probably not a ZList dump)
        logger.error('problem parsing data from dict field %s', e)
        sys.exit('Exiting')
    else:
        logger.info('completed processing ZList file %s', filepath)
        logger.info('results: %d successful, %d failed in %s seconds',
                    cnt_success, cnt_fail, time_total)

