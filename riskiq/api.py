#!/usr/bin/env python
"""
RiskIQ API
"""
__author__ = 'RiskIQ Research'
__version__ = '0.4.11'

import json
import sys
from datetime import timedelta, datetime

# sys.version_info.major exists in python>=2.7, but just a tuple python<2.7 :(
PY2 = (sys.version_info[0] == 2)
PY3 = (sys.version_info[0] == 3)
if PY2:
    import httplib
    str_type = eval('basestring')
else:
    str_type = str

import requests

from riskiq.config import Config

# Acceptable string time format for all requests
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
TIME_FORMAT_DAY = '%Y-%m-%d 00:00:00'
TIME_FORMAT_ISO = '%Y-%m-%dT%H:%M:%S.000-0000'

INVENTORY_ASSET_TYPES = ['ALL', 'WEB_SITE', 'NAME_SERVER', 'MAIL_SERVER',
                         'HOST', 'DOMAIN', 'IP_BLOCK', 'ASN', 'SSL_CERT',
                         'CONTACT']


def today():
    """
    Generates a date string for today.

    :return: Date string of today in "yyyy-mm-dd" format, accepted by API
    """
    return datetime.strftime(datetime.now(), '%Y-%m-%d')


def format_date(dt, day=False):
    """
    Generates a date string in the required format from a datetime object.

    :param dt: Datetime object
    :param day: Bool, whether to take the floor of the day
        (1 means beginning of today since midnight)
    :return: string in acceptable date format
    """
    fmt = TIME_FORMAT
    if day:
        fmt = TIME_FORMAT_DAY
    return datetime.strftime(dt, fmt)


def date_range(days=1, start=None, end=None):
    """
    Generate a start date and an end date based off of how many days.

    :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
    :param start: Override start date.
    :param end: Override end date
    :return: (start, end) tuple of strings in acceptable date format
    """
    if not any([days, start, end]):
        return None, None
    if start is None:
        start = format_date(datetime.now() - timedelta(days=days - 1), day=True)
    elif isinstance(start, datetime):
        start = format_date(start)
    elif isinstance(start, str_type):
        start = start.replace('today', today())
    if end is None:
        end = format_date(datetime.now())
    elif isinstance(end, datetime):
        end = format_date(end)
    elif isinstance(end, str_type):
        end = end.replace('today', today())
    return start, end


def set_if(dictionary, key, value):
    if value is not None:
        dictionary[key] = value


class FilterField:
    ''' Used for filter fields in /inventory/search params '''
    AssetType = 'assetType'


class FilterValue:
    ''' Used for filter values in /inventory/search params '''
    WebSite = 'WEB_SITE'


class FilterOperation:
    ''' Used for filter operations in /inventory/search params '''
    Equals = 'EQ'
    NotEqual = 'NE'
    Like = 'LIKE'
    NotLike = 'NOT_LIKE'
    Contains = 'CONTAINS'
    NotContains = 'NOT_CONTAINS'
    Null = 'NULL'
    NotNull = 'NOT_NULL'
    Between = 'BETWEEN'
    In = 'IN'
    NotIn = 'NOT_IN'
    GreaterThan = 'GT'
    GreaterThanOrEqual = 'GTE'
    LessThan = 'LT'
    LessThanOrEqual = 'LTE'


class SearchFilter(object):
    '''
    SearchFilter is used in event and inventory searches.
    Acceptable operations are | (or) and & (and).

    Operations must be formatted as a product of sums, meaning all or's must
    happen before any and's, example:

    Valid:
    ::
        (a | b) & (c | d | e)

    Invalid:
    ::
        (a & b) | (c & d)

    example usage:
    ::

        a = SearchFilter(field="value", op=FilterOperation.Contains,
                         value="value")
        b = SearchFilter(field="another", op=FilterOperation.Equals,
                         value="value")
        # a matches, or b matches
        a_or_b = a | b
        # a and b both match
        a_and_b = a & b
        # c as well as (a or b)
        c_and_ab = (c & (a | b))
        # (a or b) and (c or d)
        ab_and_cd = (a | b) & (c | d)
    '''

    def __init__(self, field=None, op=None, value=None, **kwargs):
        '''
        Creates a filter to be used for an event search.

        See:
        https://sf.riskiq.net/crawlview/api/docs/controllers/EventController.html#listSearchFields

        :param field: a field to filter against, eg. createdAt
        :param op: a comparison operator,
                   eg. GTE or FilterOperation.GreaterThanOrEqual
        :param value: a value to use, eg. a date for a createdAt filter.
        :return: a new filter
        '''
        self._wrapped_sum = kwargs.get('_wrapped_sum')
        if '_filters' in kwargs:
            self._filters = kwargs['_filters']
        elif field is None or op is None:
            raise ValueError('Must specify a field, op and value')
        else:
            self._filters = [{'field': field, 'type': op, 'value': value}]

    def __str__(self):
        return json.dumps(self.asdict())

    def __or__(self, other_filter):
        if not (self._wrapped_sum or other_filter._wrapped_sum):
            new_filters = self._filters + other_filter._filters
            return SearchFilter(_wrapped_sum=False, _filters=new_filters)
        raise SyntaxError("AND operators must be at the top level")

    def __and__(self, other_filter):
        new_filters = self._wrap_filters() + other_filter._wrap_filters()
        return SearchFilter(_wrapped_sum=True, _filters=new_filters)

    def asdict(self):
        '''return a working riskiq filter as a dictionary'''
        if self._wrapped_sum:
            return {'filters': self._filters}
        return {'filters': self._wrap_filters()}

    def _wrap_filters(self):
        if self._wrapped_sum:
            return self._filters
        return [{'filters': self._filters}]


class Client(object):
    """
    RiskIQ API Client

    Example:
    ::

        from riskiq.api import Client
        # Put credentials here.
        token, key = None, None
        client = Client(token, key)

        # Submit URLs to your project
        urls = ['http://evilexample.com/evil.php?shell=true', ...]
        client.submit_landing_page_bulk(urls, project_name='Example')

        # Get blacklist list from varying date ranges
        client.get_blacklist_list(days=5)
        data = client.get_blacklist_list(
            start="2014/08/01 00:00:00", end="today 00:00:00"
        )
        results = data['resources']
        all_malware = [x for x in results if x['malware']]
    """

    # Default seconds until socket timeout on all GETs
    # override with self._get(..., timeout=10)
    TIMEOUT = 60

    def __init__(self, token, key, server='ws.riskiq.net', version='v1',
                 http_proxy=None, https_proxy=None):
        self.api_base = 'https://%s/%s' % (server, version)
        self.auth = (token, key)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.proxies = {}
        if http_proxy:
            self.proxies['http'] = http_proxy
        if https_proxy:
            self.proxies['https'] = https_proxy

    @classmethod
    def from_config(cls):
        config = Config()
        client = cls(
            token=config.get('api_token'),
            key=config.get('api_private_key'),
            server=config.get('api_server'),
            version=config.get('api_version'),
            http_proxy=config.get('http_proxy'),
            https_proxy=config.get('https_proxy'),
        )
        return client

    def _endpoint(self, endpoint, action, *url_args):
        """
        Return the URL for the action

        :param endpoint: The controller
        :param action: The action provided by the controller
        :param url_args: Additional endpoints(for endpoints that take part of the url as option)
        :return: Full URL for the requested action
        """
        api_url = "/".join((self.api_base, endpoint, action))
        if url_args:
            api_url += "/".join(url_args)
        return api_url

    def _dump_requests(self):
        ''' Disable for Python3 '''
        if PY2:
            self._old_send = httplib.HTTPConnection.send
            old_send = self._old_send

            def new_send(self, data):
                print(data)
                return old_send(self, data)
            httplib.HTTPConnection.send = new_send

    def _undump_requests(self):
        ''' Disable for Python3 '''
        if PY2:
            httplib.HTTPConnection.send = self._old_send

    def _json(self, response):
        """
        JSON response from server

        :param response: Response from the server
        :throws ValueError: from requests' response.json() error
        :return: response deserialized from JSON
        """
        if response.status_code == 204:
            return None
        if not response.text.strip() and response.status_code == 200:
            return None
        try:
            return response.json()
        except ValueError as e:
            raise ValueError(
                'Exception: %s\n'
                'request: %s, response code: %s, response: %s' % (
                    str(e), response.request.url, response.status_code,
                    response.content,
                )
            )

    def _get(self, endpoint, action, *url_args, **url_params):
        """
        Request API Endpoint - for GET methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
            the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *url_args)
        if 'timeout' in url_params:
            timeout = url_params['timeout']
            del url_params['timeout']
        else:
            timeout = Client.TIMEOUT
        kwargs = {'auth': self.auth, 'headers': self.headers,
                  'params': url_params,
                  'timeout': timeout, 'verify': True}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = requests.get(api_url, **kwargs)
        return self._json(response)

    def _get_raw(self, endpoint, action, *url_args, **url_params):
        """
        Request API Endpoint - for GET methods that don't return JSON

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
            the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: raw response text
        """
        api_url = self._endpoint(endpoint, action, *url_args)
        if 'timeout' in url_params:
            timeout = url_params['timeout']
            del url_params['timeout']
        else:
            timeout = Client.TIMEOUT
        kwargs = {'auth': self.auth, 'headers': self.headers,
                  'params': url_params,
                  'timeout': timeout, 'verify': True}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = requests.get(api_url, **kwargs)
        return response.text

    def _post(self, endpoint, action, data, *url_args, **url_params):
        """
        Submit to API Endpoint - for POST methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
            the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *url_args)
        data = json.dumps(data)
        kwargs = {'auth': self.auth, 'headers': self.headers,
                  'params': url_params, 'verify': True, 'data': data}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = requests.post(api_url, **kwargs)
        return self._json(response)

    def get_affiliate_campaign_summary(self, days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.

        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = date_range(days, start, end)
        return self._get('affiliate', 'campaignSummary',
                         startDateInclusive=start, endDateExclusive=end)

    def _landing_page_entry(self, url=None, keyword=None,
                            md5_hash=None, project_name=None, pingback_url=None,
                            fields=None):
        """
        Build the dictionary for a single landing_page submission.

        :param url: Url to submit. Only required parameter.
        :param keyword: Optional Keyword for this landing page.
        :param md5_hash: Optional MD5 representing the canonical ID for this
            landing page
        :param project_name: Optional Project name to submit landing page to
        :param pingback_url: Optional URL to be GET requested upon completion
            of analysis of the landing page
        :param fields: Optional dictionary of custom fields
        :return: returns dictionary usable for requests
        """
        if url is None:
            raise ValueError('url param is required in landing_page submission')
        data = {}
        if url:
            data['url'] = url
        if keyword:
            data['keyword'] = keyword
        if md5_hash:
            data['md5'] = md5_hash
        if project_name:
            data['projectName'] = project_name
        if pingback_url:
            data['pingbackUrl'] = pingback_url
        if fields:
            data['fields'] = [
                {'name': t[0], 'value': t[1]}
                for t in fields.items()
            ]
        return data

    def get_affiliate_incident_list(self, known_profile=None, max_results=None,
                                    days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.

        :param known_profile: Bool, only return incidents that match a known
            profile
        :param max_results: maximum number of results to return
        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if known_profile is not None:
            kwargs['knownProfile'] = known_profile
        if max_results is not None:
            kwargs['maxResults'] = max_results
        return self._get('affiliate/incident', 'list', **kwargs)

    def get_binary_list(self, virus_total_only=None, client_workspace_only=None,
                        days=1, start=None, end=None):
        """
        Return a list of all binaries in date range

        :param virus_total_only: Bool, only include those flagged by VT
        :param client_workspace_only: Bool, only include those found in crawls
        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if virus_total_only is not None:
            kwargs['virus_total_only'] = virus_total_only
        if client_workspace_only is not None:
            kwargs['client_workspace_only'] = client_workspace_only
        return self._get('binary', 'list', **kwargs)

    def get_binary_data(self, md5_hash):
        """
        Query for the binary encoded base64 with the given md5 hash

        :param md5_hash: md5 hash of the binary data
        :return: object containing a dict with 'data' key encoded in base64
        """
        return self._get('binary', 'data', md5=md5_hash)

    def get_blacklist_lookup(self, url):
        """
        Query blacklist on url.

        :param url: URL to query blacklist on.
        :return: Blacklist Dict
        """
        result = self._get('blacklist', 'lookup', url=url)
        if result and 'description' not in result:
            result['description'] = ''
        return result

    def get_blacklist_lookup_bulk(self, urls):
        """
        Query blacklist urls in bulk.
        At least one url must be specified.

        :param urls: Array of URLs to query blacklist on.
        :return: Array of Blacklist Dicts
        """
        result = self._get('blacklist', 'bulkLookup', urls=",".join(urls))
        if result and 'lookup' not in result:
            result['lookup'] = []
        return result['lookup']

    def get_blacklist_incident(self, url, start_index=None, max_results=None,
                               **kwargs):
        """
        Query blacklist incidents by url.

        :param url: URL to query blacklist on.
        :return: Blacklist incident
        """
        url_params = {'url': url}
        if start_index is not None:
            url_params['startIndex'] = start_index
        if max_results is not None:
            url_params['maxResults'] = max_results
        return self._get('blacklist', 'incident', **url_params)

    def get_blacklist_incident_list(self, all_workspace_crawls=None, days=1,
                                    start=None, end=None, timeout=None,
                                    **kwargs):
        """
        Query blacklist incidents

        :param url: list of blacklist incidents within timeframe
        :param all_workspace_crawls:False by default, filtered to crawls that
            are either landing pages, site scanning, or matching a brand
            classifier
        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: Blacklist list
        """
        start, end = date_range(days, start, end)
        url_params = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if all_workspace_crawls is not None:
            url_params['all_workspace_crawls'] = all_workspace_crawls
        if timeout is not None:
            url_params['timeout'] = timeout
        return self._get('blacklist/incident', 'list', **url_params)

    def get_blacklist_list(self, blacklist_filter=None, days=1, start=None,
                           end=None, **kwargs):
        """
        Query blacklisted resources

        :param blacklist_filter: None, or one of
            'blackhole', 'sakura', 'exploitKit'
        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all blacklisted resources
        """
        start, end = date_range(days, start, end)
        url_params = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if blacklist_filter is not None:
            url_params['filter'] = blacklist_filter
        return self._get('blacklist', 'list', **url_params)

    def get_blacklist_malware(self, blacklist_filter=None, confidence=None,
                              days=1, start=None, end=None, **kwargs):
        """
        Query for all discovered malware resources generated within a
        particular period.

        :param blacklist_filter: None, or one of
            'blackhole', 'sakura', 'exploitKit'
        :param confidence: to restrict the result set by malicious probability
            'H', 'M', 'L' (high, medium, low)
        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all blacklisted resources
        """
        start, end = date_range(days, start, end)
        url_params = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if blacklist_filter is not None:
            url_params['filter'] = blacklist_filter
        if confidence is not None:
            url_params['confidence'] = confidence
        return self._get('blacklist', 'malware', **url_params)

    def __get_blacklist_exploit_binary(self, days=1, start=None, end=None,
                                       **kwargs):
        """
        Query for all PE format binaries on webpages used for exploitation

        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all binaries
        """
        raise NotImplementedError('Not implemented server-side')
        start, end = date_range(days, start, end)
        url_params = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        return self._get('blacklist', 'exploitBinary', **url_params)

    def get_crawl_volume_daily_summary(self, days=1, start=None, end=None):
        """
        Query for the crawl volume daily summary report for the date range

        :param days: How many days to include from today(for generating 30 day
            time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: crawl volume daily summary
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateInclusive': end,
        }
        return self._get('crawlVolume', 'dailySummary', **kwargs)

    def get_dns_data_by_name(self, name, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by hostname.

        :param name: hostname to query. Can also use wildcards, e.g. *.test.com
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'name', name=name, rrType=rrtype,
                         maxResults=maxresults)

    def get_dns_data_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data

        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'data', ip=ip, rrType=rrtype,
                         maxResults=maxresults)

    def get_dns_ptr_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the reverse dns of a particular IP.

        :param ip: IP Address to Query.
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'name', ip=ip, rrType=rrtype,
                         maxResults=maxresults)

    def get_dns_data_by_data(self, hostname, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data

        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'data', name=hostname, rrType=rrtype,
                         maxResults=maxresults)

    def get_landing_page(self, md5_hash, whois=None):
        """
        Retrieve a single landing page by MD5.

        :param md5_hash: md5 of the landing page
        :param whois: Bool, whether to include whois information
        :return: landing page data
        """
        kwargs = {}
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', md5_hash, **kwargs)

    def submit_landing_page(self, url, **kwargs):
        """
        Submit a single landing page.

        :param url: Url to submit. Only required parameter.
        :param keyword: Optional Keyword for this landing page.
        :param md5_hash: Optional MD5 representing the canonical ID for this
            landing page
        :param project_name: Optional Project name to submit landing page to
        :param pingback_url: Optional URL to be GET requested upon completion
            of analysis of the landing page
        :param fields: Optional dictionary of custom fields
        :return: returns json of landing page.
        """
        kwargs.update({'url': url})
        data = self._landing_page_entry(**kwargs)
        return self._post('landingPage', '', data)

    def get_landing_page_crawled(self, whois=None, days=None, start=None,
                                 end=None):
        """
        List landing pages by crawl date - maximum of 100

        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        if any([days, start, end]):
            kwargs = {'start': start, 'end': end}
        else:
            kwargs = {}
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', 'crawled', **kwargs)

    def get_landing_page_flagged(self, whois=None, days=None, start=None,
                                 end=None):
        """
        List landing pages by known profile creation date - maximum of 100

        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        if any([days, start, end]):
            kwargs = {'start': start, 'end': end}
        else:
            kwargs = {}
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', 'flagged', **kwargs)

    def __submit_landing_page_urls(self, urls, **kwargs):
        """
        Submit landing pages in bulk. This is the old form of
        submit_landing_page_bulk, and does not offer the full features of the
        API. See submit_landing_page_bulk.

        :param urls: Urls to submit.
        :param project_name: Project name to submit landing page to
        :return: returns json of landing page.
        """
        project_name = kwargs.get('project_name')
        if project_name is not None:
            data = {
                'entry': [
                    {
                        'url': url,
                        'projectName': project_name
                    }
                    for url in urls
                ]
            }
        else:
            data = {'entry': [{'url': url} for url in urls]}
        return self._post('landingPage', 'bulk', data)

    def submit_landing_page_bulk(self, entries, **kwargs):
        """
        Submit landing pages in bulk
        At least url must be specified.

        :param entries: list of dictionaries specifying the below

        :entry_key url: Url to submit.
        :entry_key keyword: Optional Keyword for this landing page.
        :entry_key md5_hash: Optional MD5 representing the canonical ID for this
            landing page
        :entry_key project_name: Optional Project name to submit landing page to
        :entry_key pingback_url: Optional URL to be GET requested upon completion
            of analysis of the landing page
        :entry_key fields: Optional dictionary of custom fields
        :return: returns json of landing page bulk request.
        """
        # Check to see if entries is a list of urls via the old API call.
        # We need to check this for backwards compatibility.
        if len(entries) > 0 and isinstance(entries[0], str_type):
            return self.__submit_landing_page_urls(entries, **kwargs)
        # It's new style, so build it from the list of dictionaries.
        data = {'entry': [
            self._landing_page_entry(**entry)
            for entry in entries
        ]}
        return self._post('landingPage', 'bulk', data)

    def get_landing_page_malicious_binary(self, whois=None, days=1, start=None,
                                          end=None):
        """
        List landing pages with malicious binary incidents.

        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        url_params = {'start': start, 'end': end}
        if whois is not None:
            url_params['whois'] = whois
        return self._get('landingPage', 'maliciousBinary', **url_params)

    def get_landing_page_projects(self):
        """
        List all projects that landing pages may be submitted to.

        :return: all projects
        """
        return self._get('landingPage', 'projects')

    def get_android(self, package_name):
        """
        Retrieve an android application by package name.
        If the app is not found, 404 NOT FOUND is returned.

        :param package_name: name of android package
        :return: the requested app
        """
        return self._get('mobile/android', package_name)

    def get_android_lookup(self, url):
        """
        Retrieve an android app by store URL.
        The store URL should be of the form
        https://play.google.com/store/apps/details?id=[package name]

        :param url: The store URL
        :return: app details
        """
        return self._get('mobile/android', 'lookup', url=url)

    def get_mobile_incident(self, incident_id):
        """
        Retrieve an mobile app incident by ID.
        If the incident is not found, 404 NOT FOUND is returned.

        :param incident_id: Long int ID
        :return: mobile incident
        """
        return self._get('mobile/incident', '%d' % incident_id)

    def get_mobile_incident_list(self, days=1, start=None, end=None):
        """
        List app incidents by their incident creation date.

        :param days: How many days you want to grab
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: mobile incidents
        """
        start, end = date_range(days, start, end)
        return self._get('mobile/incident', 'list', startDateInclusive=start,
                         endDateExclusive=end)

    def get_page(self, crawl_guid, page_guid):
        """
        retrieve a page and return it

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :return: requested page
        """
        return self._get_raw('page', '%s/%s' % (crawl_guid, page_guid))

    def get_page_dom(self, crawl_guid, page_guid):
        """
        retrieve a page and return its DOM

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :return: requested page
        """
        return self._get_raw('page', '%s/%s/dom' % (crawl_guid, page_guid))

    def get_page_response(self, crawl_guid, page_guid):
        """
        retrieve a page and return it

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :return: requested page
        """
        return self._get('page', '%s/%s/response' % (crawl_guid, page_guid))

    def get_page_child_dom(self, crawl_guid, page_guid, child_guid):
        """
        retrieve a page and return its DOM

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :param child_guid: child GUID
        :return: requested page
        """
        return self._get('page', '%s/%s/%s/dom' % (crawl_guid, page_guid,
                                                   child_guid))

    def get_page_child_dom_text(self, crawl_guid, page_guid, child_guid):
        """
        retrieve a page and return its DOM text

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :param child_guid: child GUID
        :return: requested page
        """
        return self._get('page', '%s/%s/%s/domText' % (crawl_guid, page_guid,
                                                       child_guid))

    def get_page_child_response(self, crawl_guid, page_guid, child_guid):
        """
        retrieve a page and return its response

        :param crawl_guid: crawl GUID
        :param page_guid: page GUID
        :param child_guid: child GUID
        :return: requested page
        """
        return self._get('page', '%s/%s/%s/response' % (crawl_guid, page_guid,
                                                        child_guid))

    def get_project_list(self):
        """
        List all projects.
        """
        return self._get('project', 'list')

    def get_project_keywords(self, project_id):
        """
        List all keywords associated to specified project.

        :param project_id: Integer ID of the project
        :return: Keywords of project
        """
        return self._get('project', '%d/keywords' % project_id)

    def get_proxy_ip(self, ip):
        """
        Lookup a proxy by IP

        :param ip: ip address of proxy
        :return: proxy
        """
        return self._get('proxy', 'ip/%s' % ip)

    def get_zlist_urls(self, days=1, start=None, end=None):
        """
        Get the current zlist urls.

        :param days: How many days you want to grab
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: all URLs
        """
        start, end = date_range(days, start, end)
        return self._get('zlist', 'urls', start=start, end=end)

    def get_whois(self, domain, history=None):
        """
        Return the whois record for a domain.

        :param domain: Domain to query
        :param history: Whether to include historical whois records.
        :return: list of whois record dictionaries
        """
        return self._get('whois', domain, history=history)

    def post_whois(self, domain=None, email=None, name_server=None, raw=None,
                   max_results=100):
        """
        Query whois results for a domain, email, name_server.
        Allows * for wildcard.

        :param domain: Domain to query
        :param email: email address to query
        :param name_server: name server to query
        :param raw: raw data to query
        :param max_results: max results to return, default 100
        :return: list of domain dictionaries
        """
        data = {'maxResults': max_results}
        set_if(data, 'domain', domain)
        set_if(data, 'email', email)
        set_if(data, 'nameServer', name_server)
        set_if(data, 'raw', raw)
        return self._post('whois', 'query', data)

    def get_inventory(self, asset_id=None):
        """
        Retrieve a single inventory item by its assetID

        :param asset_id: assetID for the item to retreive
        :return: inventory item data
        """
        # actual_url = 'inventory/' + asset_id
        return self._get('inventory', asset_id, '')

    def post_inventory_search(self, query=None, filter=None, filters=None):
        """
        Search the inventory based on a query and filters

        This one is a bit complex since the input to the HTTP endpoint is.
        https://sf.riskiq.net/crawlview/api/docs/controllers/InventoryController.html#search
        If you pass filter, you request {'filters': [{'filters: [filter]}]}
        If you pass filters, you request {'filters': [{'filters': filters}]}
        If filters is a list of lists, you separate those out at the top level
        list.

        :param query: optional query string
        :param filter: either a dict which uses a single filter,
                       or list of filters
        :param filters: for passing in multiple filters
        :return: inventory search results
        """
        if filter:
            filters_list = [{'filters': [filter]}]
        elif filters and isinstance(filters[0], (list, tuple)):
            filters_list = [{'filters': filter_group}
                            for filter_group in filters]
        elif filters and isinstance(filters[0], dict):
            filters_list = [{'filters': filters}]
        else:
            return None
        data = {'filters': filters_list}
        set_if(data, 'query', query)
        return self._post('inventory', 'search', data)

    def post_event_search(self, event_filter, count=50, offset=0):
        '''
        Perform event search based on a filter. See SearchFilter for help on
        creating an event filter.

        :param event_filter: a valid riskiq filter
        :param offset: offset, default 0
        :param count: number of results returned, default 50
        :return: list of domain dictionaries
        '''
        return self._post('event', 'search', event_filter, count=count,
                          offset=offset)

    def post_event_update(self, ids, reviewCode=None, eventPriority=None,
                          owner=None, country=None, tags=None, note=None):
        '''
        Update a list of events.

        :param ids: a list of ids to update
        :param reviewCode: maps to status
        :param eventPriority: Event Priority to update events with
               i.e. Critical, Major, Medium, Minor, Trivial
        :param owner: Owner to update events with by username
        :param country: Review code to update events with code or full name
                        i.e. either "cn" or "China"
        :param tags: Tag to update events with by tag option.
                     Eventually we will convert over to the ways assets do
                     tagging; so we will not have to guess at the option.
                     If you'd like to bemore specific for now, "category:option"
                     will be handled.
        :param note: Add a message to this event.
        '''
        data = {}
        data['ids'] = ids
        set_if(data, 'reviewCode', reviewCode)
        set_if(data, 'eventPriority', eventPriority)
        set_if(data, 'owner', owner)
        set_if(data, 'country', country)
        set_if(data, 'tags', tags)
        set_if(data, 'note', note)
        self._post('event', 'update', data)
