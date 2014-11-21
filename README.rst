riskiq 
======

*Python client API for RiskIQ services*

**riskiq** provides a Python client library implementation into RiskIQ API
services. The library currently provides support for the following services:

- Passive DNS queries
- Blacklist URL search
- Blacklist Incident URL search
- ZList download
- Crawler *Landing Page* submission

Command-line scripts
--------------------

The following command line scripts are installed with the library:

- **riq-config**: utility to set API configuration options for the library
  (API token and private key).
- **riq-dns**: client to issue queries to the RiskIQ Passive DNS database service.
- **riq-blacklist**: client to issue queries for domains and URLs to identify
  listings in the RiskIQ blacklist.
- **riq-zlist**: query the zlist for entries within a time range
- **riq-landingpage**: get and submit new landing pages

See the *Use* section for information on usage.

Installation
------------

    $ python setup.py install
    # or from PyPI
    # sudo pip install riskiq

The package depends on the Python Requests_ library.
If Requests is not installed, it will be installed as a result of the above command.

.. _Requests: http://docs.python-requests.org/

Setup
-----

First-time setup requires configuring an API token and private key for authentication.

    $ riq-config -t <API_TOKEN> -k <API_PRIVATE_KEY>

At any time, the current API configuration parameters can be queried using the same utility:

    $ riq-config -p

Configuration parameters are stored in $HOME/.config/riskiq/api_config.json

Use
---

Every command-line script has several sub-commands that may be passed to it. The
commands usage may be described with the -h/--help option.

Eg.::

    $ riq-blacklist -h
    usage: riq-blacklist [-h] {lookup,incident,incidentlist,list,malware} ...

    positional arguments:
      {lookup,incident,incidentlist,list,malware}
        lookup              Query blacklist on URL
        incident            Query blacklist incident on URL
        incidentlist        query blacklist incidents within timeframe
        list                query blacklisted resources
        malware             Query for all discovered malware resources generated
                            within a particular period.

    optional arguments:
      -h, --help            show this help message and exit

Every sub-command has further help options:::

    $ riq-blacklist lookup -h
    usage: riq-blacklist lookup [-h] [-l] [-j] urls [urls ...]

    positional arguments:
      urls

    optional arguments:
      -h, --help     show this help message and exit
      -l, --oneline  Output one line per entry
      -j, --json     Output as JSON

All commands will have the -j/--json option to return raw responses in JSON
format, which often contain more information than present in the default,
human readable format.

Version History
---------------

Up until 0.2.7 it has been mostly base implementation and bug fixes.
I do not recommend using anything less that 0.2.7.

:0.2.7:
    Fixed template bug in `riq-landingpage submit`
:0.2.6:
    Fix landingpage submissions to allow md5, project, keyword, fields
:0.2.5:
    Added binary download options --output and --output-dir
    8f540b0 List and download suspicious binaries via CLI
    fix MANIFEST.in installation bug
:0.2.3:
    Documentation changes
:0.2.1:
    Added documentation
:<= 0.2.0:
    Most implementation of CLI tools and client API
