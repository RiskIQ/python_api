#!/usr/bin/env python
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

setup(
    name = 'libriskiq',
    version = '0.1',
    packages = find_packages(),
    install_requires = ['requests'],
    entry_points = {
        'console_scripts': [
            'riq-pdns = libriskiq.cli.pdns:main',
            'riq-config = libriskiq.cli.config:main',
        ]
    }
)
