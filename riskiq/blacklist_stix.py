#!/usr/bin/env python
import json
import argparse
from datetime import datetime

from stix.core import STIXPackage, STIXHeader
from stix.utils import set_id_namespace
from stix.common.vocabs import PackageIntent
from stix.common import InformationSource
from cybox.common import Time
from stix.indicator import Indicator
from cybox.objects.uri_object import URI

def load_bldata(path):
    # Read the json data
    if isinstance(path, dict):
        data = path
    else:
        with open(path) as blFile:
            data = json.load(blFile)
    if 'resources' in data:
        return data['resources']
    elif 'incident' in data:
        return [x['resource'] for x in data['incident']]
    else:
        raise RuntimeError('Invalid JSON file. Please use riq-blacklist '
            'malware output, or riq-blacklist incidents')

def dump_xml(out_path, output_xml):
    if out_path == '-':
        print(output_xml)
    else:
        with open(out_path, 'w') as f:
            f.write(output_xml)

def stix_xml(bldata):
    # Create the STIX Package and Header objects
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    # Set the description
    stix_header.description = "RiskIQ Blacklist Data - STIX Format"
    # Set the namespace
    NAMESPACE = {"http://www.riskiq.com" : "RiskIQ"}
    set_id_namespace(NAMESPACE) 
    # Set the produced time to now
    stix_header.information_source = InformationSource()
    stix_header.information_source.time = Time()
    stix_header.information_source.time.produced_time = datetime.now()
    # Create the STIX Package
    stix_package = STIXPackage()
    # Build document
    stix_package.stix_header = stix_header
    # Build the Package Intent
    stix_header.package_intents.append(PackageIntent.TERM_INDICATORS)

    # Build the indicator
    indicator = Indicator()
    indicator.title = "List of Malicious URLs detected by RiskIQ - Malware, Phishing, and Spam"
    indicator.add_indicator_type("URL Watchlist")
    for datum in bldata:
        url = URI()
        url.value = ""
        url.value = datum['url']
        url.type_ =  URI.TYPE_URL
        url.condition = "Equals"
        indicator.add_observable(url)

    stix_package.add_indicator(indicator)
    return stix_package.to_xml()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('json_file', help='path to blacklist json file')
    parser.add_argument('--output', '-o', help='path to output, default:stdout',
        default='-')
    args = parser.parse_args()
    bldata = load_bldata(args.json_file)
    output_xml = stix_xml(bldata)
    dump_xml(args.output, output_xml)

if __name__ == '__main__':
    main()
