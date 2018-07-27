#!/usr/bin/env python
import os
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = 'riskiq',
    version = '0.4.12',
    description = 'client for RiskIQ REST API',
    url = "https://github.com/riskiq/python_api",
    keywords = 'riskiq API REST',
    author = "Research Team, RiskIQ",
    author_email = "research@riskiq.net",
    license = "GPLv2",
    packages = find_packages(),
    install_requires = ['requests', 'jinja2'],
    extras_require = {
        'stix': ['stix'],
    },
    long_description=read('README.rst'),
    classifiers=[
        #'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        #'Development Status :: 5 - Production/Stable',
        #'Development Status :: 6 - Mature',
    ],
    entry_points = {
        'console_scripts': [
            'riq-dns = riskiq.cli.dns:main',
            'riq-config = riskiq.cli.config:main',
            'riq-blacklist = riskiq.cli.blacklist:main',
            'riq-zlist = riskiq.cli.zlist:main',
            'riq-landingpage = riskiq.cli.landingpage:main',
            'riq-binary = riskiq.cli.binary:main',
            'riq-whois = riskiq.cli.whois:main',
            'riq-stix = riskiq.blacklist_stix:main [stix]',
            #'riq-mobile = riskiq.cli.mobile:main',
        ],
    },
    package_data = {
        'riskiq': [
            'templates/blacklist/*',
            'templates/dns/*',
            'templates/zlist/*',
            'templates/landingpage/*',
            'templates/whois/*',
        ],
    },
    include_package_data = True,
    zip_safe=False,
)
