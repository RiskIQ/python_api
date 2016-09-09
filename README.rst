riskiq 
======

*Python client for RiskIQ API services*

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

- **riq-config**: utility to set or query API configuration options for the
  library (API token and private key).
- **riq-dns**: client to issue queries to the RiskIQ Passive DNS database service.
- **riq-blacklist**: client to issue queries for domains and URLs to identify
  listings in the RiskIQ blacklist.
- **riq-zlist**: query the zlist for entries within a time range
- **riq-landingpage**: get and submit new landing pages
- **riq-binary**: list and download files from the binary feed

See the *Usage* section for more information.

Installation
------------

From the downloaded source distribution::

    $ python setup.py install

Or from PyPI::

    $ pip install riskiq

The package depends on the Python Requests_ library.
If Requests is not installed, it will be installed as a dependency.

.. _Requests: http://docs.python-requests.org/

Setup
-----

First-time setup requires configuring your API token and private key for authentication::

    $ riq-config setup <API_TOKEN> <API_PRIVATE_KEY>

At any time, the current API configuration parameters can be queried using the same utility::

    $ riq-config show

Configuration parameters are stored in **$HOME/.config/riskiq/api_config.json**.

Usage
-----

Every command-line script has several sub-commands that may be passed to it. The
commands usage may be described with the ``-h/--help`` option.

For example::

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

All commands will have the ``-j/--json`` option to return raw responses in JSON
format, which often contain more information than present in the default,
human readable format.

Version History
---------------

Versions before 0.2.7 have been mostly base implementation and bug fixes.
We do not recommend using anything less than 0.2.7.

:0.4.10:
    Added support for whois history lookups in API.
:0.4.9:
    Added support for bulk blacklist lookups in API.
:0.4.8:
    Added custom jinja2 template option to CLI render script (--template/-T)
    Fixed whitespace rendering when incidents are empty
:0.4.7:
    Hotfix for rendering bug
:0.4.6:
    Fixed multiple blacklist templates
    Fixed verbose flag for riq-blacklist submodules
:0.4.5:
    Fixed bugs in riskiq.cli.blacklist scripts
:0.4.4:
    Refactored riskiq.cli.blacklist scripts
:0.4.3:
    Fixed issue where Python 2.6 sys.version_info is a tuple, not namedtuple.
:0.4.2:
    Fixed config bug
:0.4.1:
    Disable httplib if in Python 3+
:0.4.0:
    Working on Python 3 compatibility
:0.3.2:
    Updated ``riq-dns`` output formats. Default output format is now a
    shortened one-line format per record. A more verbose one-line format
    is available with the ``-v/--verbose`` option. The previous text-based
    "human-readable" format is available using the ``-T/--text`` option.
:0.2.7:
    Fixed template bug in ``riq-landingpage submit``
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
