#!/usr/bin/env python
"""
RiskIQ API
"""
__author__ = 'RiskIQ Research'
__version__ = '0.1-ALPHA'
import json
from datetime import timedelta, datetime

import requests

# Acceptable string time format for all requests
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
TIME_FORMAT_DAY = '%Y-%m-%d 00:00:00'

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
    :param days: How many days to include from today(for generating 30 day time windows, etc.)
    :param start: Override start date.
    :param end: Override end date
    :return: (start, end) tuple of strings in acceptable date format
    """
    if not any([days, start, end]):
        return None, None
    if start is None:
        start = format_date(datetime.now() - timedelta(days=days-1), day=True)
    elif isinstance(start, datetime):
        start = format_date(start)
    if end is None:
        end = format_date(datetime.now())
    elif isinstance(end, datetime):
        end = format_date(end)
    return start, end

class Client(object):
    """
    RiskIQ API Client
    """
    def __init__(self, token, key, server='ws.riskiq.net', version='v1'):
        self.api_base = 'https://%s/%s' % (server, version)
        self.auth = (token, key)
        self.headers = {
            'Accept': 'Application/JSON',
            'Content-Type': 'Application/JSON',
        }

    def _endpoint(self, endpoint, action, *urlparams, **params):
        """
        Return the URL for the action
        :param endpoint: The controller
        :param action: The action provided by the controller
        :param urlparams: Additional endpoints(for endpoints that take part of the url as option)
        :param params: Parameters to pass to url, typically query string
        :return: Full URL for the requested action
        """
        api_url = "/".join((self.api_base, endpoint, action))
        if urlparams:
            api_url += "/".join(urlparams)
        return api_url
    
    def _json(self, response):
        """
        JSON response from server
        :param response: Response from the server
        :throws ValueError: from requests' response.json() error
        :return: response deserialized from JSON
        """
        if response.status_code == 204:
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

    def _get(self, endpoint, action, *urlparams, **params):
        """
        Request API Endpoint - for GET methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param urlparams: Additional endpoints(for endpoints that take part of the url as option)
        :param params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *urlparams, **params)
        response = requests.get(api_url, auth=self.auth, headers=self.headers,
            verify=True, params=params)
        return self._json(response)

    def _post(self, endpoint, action, data, *urlparams, **params):
        """
        Submit to API Endpoint - for POST methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param urlparams: Additional endpoints(for endpoints that take part of the url as option)
        :param params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *urlparams, **params)
        data = json.dumps(data)
        response = requests.post(api_url, auth=self.auth, headers=self.headers, verify=True, data=data, params=params)
        return self._json(response)

    def get_affiliate_campaign_summary(self, days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = date_range(days, start, end)
        return self._get('affiliate', 'campaignSummary', 
            startDateInclusive=start, endDateExclusive=end)

    def get_affiliate_incident_list(self, known_profile=None, 
        max_results=None, days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.
        :param known_profile: Bool, only return incidents that match a known profile
        :param max_results: maximum number of results to return
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
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
    
    def get_binary_list(self, virus_total_only=None,
            client_workspace_only=None, days=1, start=None, end=None):
        """
        Return a list of all binaries in date range
        :param virus_total_only: Bool, only include those flagged by VT
        :param client_workspace_only: Bool, only include those found in crawls
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
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

    def get_blacklist_incident(self, url):
        """
        Query blacklist incidents by url.
        :param url: URL to query blacklist on.
        :return: Blacklist incident
        """
        return self._get('blacklist', 'incident', url=url)

    def get_blacklist_incident_list(self, all_workspace_crawls=None, 
        days=1, start=None, end=None):
        """
        Query blacklist incidents
        :param url: list of blacklist incidents within timeframe
        :param all_workspace_crawls:False by default, filtered to crawls that 
            are either landing pages, site scanning, or matching a brand 
            classifier
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: Blacklist list
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if all_workspace_crawls is not None:
            kwargs['all_workspace_crawls'] = all_workspace_crawls
        return self._get('blacklist/incident', 'list', **kwargs)

    def get_blacklist_list(self, blacklist_filter=None, 
        days=1, start=None, end=None):
        """
        Query blacklisted resources
        :param blacklist_filter: None, or one of
            'blackhole', 'sakura', 'exploitKit'
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all blacklisted resources
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if blacklist_filter is not None:
            kwargs['filter'] = blacklist_filter
        return self._get('blacklist', 'list', **kwargs)

    def get_blacklist_malware(self, blacklist_filter=None, confidence=None,
        days=1, start=None, end=None):
        """
        Query blacklist incidents by url.
        :param blacklist_filter: None, or one of
            'blackhole', 'sakura', 'exploitKit'
        :param confidence: to restrict the result set by malicious probability
            'H', 'M', 'L' (high, medium, low)
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all blacklisted resources
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if blacklist_filter is not None:
            kwargs['filter'] = blacklist_filter
        if confidence is not None:
            kwargs['confidence'] = confidence
        return self._get('blacklist', 'malware', **kwargs)

    def get_blacklist_exploit_binary(self, days=1, start=None, end=None):
        """
        Query for all PE format binaries on webpages used for exploitation
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: all binaries
        """
        start, end = date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        return self._get('blacklist', 'exploitBinary', **kwargs)

    def get_crawl_volume_daily_summary(self, days=1, start=None, end=None):
        """
        Query for the crawl volume daily summary report for the date range
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
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

    def get_zlist_urls(self, days=1, start=None, end=None):
        """
        Get the current zlist urls.
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return:
        """
        start, end = date_range(days, start, end)
        return self._get('zlist', 'urls', start=start, end=end)

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

    def get_dns_data_by_data(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data
        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'data', name=ip, rrType=rrtype, 
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

    def submit_landing_page(self, url, project_name=None):
        """
        Submit a single landing page.
        :param url: Url to submit.
        :param project_name: Project name to submit landing page to
        :return: returns json of landing page.
        """
        data = {'url': url}
        if project_name:
            data['projectName'] = project_name
        return self._post('landingPage', '', data)

    def get_landing_page_crawled(self, whois=None,
        days=None, start=None, end=None):
        """
        List landing pages by crawl date - maximum of 100
        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        if any([days, start, end]):
            kwargs = { 'start': start, 'end': end }
        else:
            kwargs = {}
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', 'crawled', **kwargs)

    def get_landing_page_flagged(self, whois=None,
        days=None, start=None, end=None):
        """
        List landing pages by known profile creation date - maximum of 100
        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        if any([days, start, end]):
            kwargs = { 'start': start, 'end': end }
        else:
            kwargs = {}
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', 'flagged', **kwargs)

    def submit_landing_page_bulk(self, urls):
        """
        Submit landing pages in bulk
        :param urls: Urls to submit.
        :param project_name: Project name to submit landing page to
        :return: returns json of landing page.
        """
        data = {'entry': [{'url': url} for url in urls]}
        return self._post('landingPage', 'bulk', data)

    def get_landing_page_malicious_binary(self, whois=None,
        days=1, start=None, end=None):
        """
        List landing pages with malicious binary incidents.
        :param whois: Bool, whether to include whois information
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return: landing page data
        """
        start, end = date_range(days, start, end)
        kwargs = { 'start': start, 'end': end }
        if whois is not None:
            kwargs['whois'] = whois
        return self._get('landingPage', 'maliciousBinary', **kwargs)

