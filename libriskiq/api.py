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
        self.headers = {'Accept': 'Application/JSON', 'Content-Type': 'Application/JSON'}
        self.time_format = '%Y-%m-%d'

    def _get_endpoint(self, endpoint, action, *urlparams, **params):
        api_url = "/".join((self.api_base, endpoint, action))
        if urlparams:
            api_url += "/".join(urlparams)
        return api_url

    def _request(self, endpoint, action, *urlparams, **params):
        """
        Request API Endpoint, this is for GET methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param urlparams: Additional endpoints(for endpoints that take part of the url as option)
        :param params: Parameters to pass to url, typically query string
        :return:
        """
        api_url = self._get_endpoint(endpoint, action, *urlparams, **params)
        response = requests.get(api_url, auth=self.auth, headers=self.headers, verify=True, params=params)
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except:
            raise ValueError('Error Parsing JSON, request: %s, response code: %s, response: %s' %
                             (response.request.url, response.status_code, response.content))

    def _submit(self, endpoint, action, data, *urlparams, **params):
        """
        Submit to API Endpoint, this is for POST methods.

        :param endpoint: Endpoint
        :param action: Endpoint Action
        :param urlparams: Additional endpoints(for endpoints that take part of the url as option)
        :param params: Parameters to pass to url, typically query string
        :return:
        """
        api_url = self._get_endpoint(endpoint, action, *urlparams, **params)
        data = json.dumps(data)
        response = requests.post(api_url, auth=self.auth, headers=self.headers, verify=True, data=data, params=params)
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except:
            raise ValueError('Error Parsing JSON, request: %s, response code: %s, response: %s' %
                            (response.request.url, response.status_code, response.content))

    def _generate_date_range(self, days=1, start=None, end=None):
        """
        Generate a start date and an end date based off of how many days. For use with inclusive dates.
        :param days: How many days to include from today(for generating 30 day time windows, etc.)
        :param start: Override start date.
        :param end: Override end date
        :return: start, end
        """
        if not start or days > 1:
            start = datetime.strftime(datetime.now() - timedelta(days=days), self.time_format)
        if not end or days > 1:
            end = datetime.strftime(datetime.now(), self.time_format)
        return start, end

    def get_blacklist_lookup(self, url):
        """
        Query blacklist on url.
        :param url: URL to query blacklist on.
        :return: Blacklist Dict
        """
        return self._request('blacklist', 'lookup', url=url)

    def get_blacklist_incident(self, url):
        """
        Query blacklist incidents by url.
        :param url: URL to query blacklist on.
        :return: Blacklist Dict
        """
        return self._request('blacklist', 'incident', url=url)

    def get_zlist_urls(self, days=1, start=None, end=None):
        """
        Get the current zlist urls.
        :param days: How many days you want to grab(if this is set, start and end are ignored)
        :param start: Which date to start from, use time_format.
        :param end: Date to end, use time_format.
        :return:
        """
        start, end = self._generate_date_range(days, start, end)
        return self._request('zlist', 'urls', start=start, end=end)

    def get_pdns_data_by_name(self, name, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by hostname.
        :param name: hostname to query. Can also use wildcards, e.g. *.test.com
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._request('dns', 'name', name=name, rrType=rrtype, maxResults=maxresults)

    def get_pdns_data_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data
        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._request('dns', 'data', ip=ip, rrType=rrtype, maxResults=maxresults)

    def get_pdns_ptr_by_ip(self, ip, rrtype=None, maxresults=1000):
        """
        Get the reverse dns of a particular IP.
        :param ip: IP Address to Query.
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._request('dns', 'name', ip=ip, rrType=rrtype, maxResults=maxresults)

    def get_pdns_data_by_data(self, ip, rrtype=None, maxresults=1000):
        """
        Get the passive dns results by ip address, query data
        :param ip: IP address of query, can also include wildcard, e.g. 192.168.0.*
        :param rrtype: Record Type to limit searches to
        :param maxresults: Max Results to Return(default 1,000)
        :return: return a JSON object of the data
        """
        return self._request('dns', 'data', name=ip, rrType=rrtype, maxResults=maxresults)

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
        return self._submit('landingPage', '', data)
