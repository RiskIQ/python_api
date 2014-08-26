#!/usr/bin/env python
"""
RiskIQ API
"""
__author__ = 'RiskIQ Research'
__version__ = '0.1-ALPHA'
import requests
from datetime import timedelta
from datetime import datetime
import json


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
        self.time_format = '%Y-%m-%d'

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

    def _date(self, day):
        """
        Generates a date string in the required format from a datetime object.
        :param day: Datetime object
        :return: string in acceptable date format
        """
        return datetime.strftime(day, self.time_format)

    def _date_range(self, days=1, start=None, end=None):
        """
        Generate a start date and an end date based off of how many days. 
        For use with inclusive dates.
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: (start, end) tuple of strings in acceptable date format
        """
        if start is None or days > 1:
            start = datetime.strftime(datetime.now() - timedelta(days=days), 
                self.time_format)
        if end is None or days > 1:
            end = datetime.strftime(datetime.now(), self.time_format)
        return start, end

    def get_affiliate_campaign_summary(self, days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = self._date_range(days, start, end)
        return self._get('affiliate', 'campaignSummary', 
            startDateInclusive=start, endDateExclusive=end)

    def get_affiliate_incident_list(self, known_profile=None, 
        max_results=None, days=1, start=None, end=None):
        """
        Return the affiliate campaign summary report for the given date range.
        :param known_profile: Boolean, only return incidents that match a known profile
        :param max_results: maximum number of results to return
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: data containing the number of results and the objects
        """
        start, end = self._date_range(days, start, end)
        kwargs = {
            'startDateInclusive': start,
            'endDateExclusive': end,
        }
        if known_profile is not None:
            kwargs['knownProfile'] = known_profile
        if max_results is not None:
            kwargs['maxResults'] = max_results
        return self._get('affiliate/incident', 'list', **kwargs)

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
        :return: Blacklist Dict
        """
        return self._get('blacklist', 'incident', url=url)

    def get_zlist_urls(self, days=1, start=None, end=None):
        """
        Get the current zlist urls.
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return:
        """
        start, end = self._date_range(days, start, end)
        return self._get('zlist', 'urls', start=start, end=end)

    def get_pdns_data_by_name(self, name, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by hostname.
        :param name: hostname to query. Can also use wildcards, e.g. *.test.com
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'name', name=name, rrType=rrtype,
            maxResults=maxresults)

    def get_pdns_data_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data
        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'data', ip=ip, rrType=rrtype,
            maxResults=maxresults)

    def get_pdns_ptr_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the reverse dns of a particular IP.
        :param ip: IP Address to Query.
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'name', ip=ip, rrType=rrtype,
            maxResults=maxresults)

    def get_pdns_data_by_data(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data
        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._get('dns', 'data', name=ip, rrType=rrtype, maxResults=maxresults)

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
