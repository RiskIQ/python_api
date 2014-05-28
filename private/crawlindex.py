__author__ = 'jpleger'
import requests


class CrawlIndexResult(object):
    _crawl_url = 'https://sf.riskiq.net/crawlview/crawlState/view/%s'

    def __init__(self, results, query_type):
        self._results = results
        self._query_type = query_type

    @property
    def ips(self):
        if 'ip' in self._results:
            return self._results['ip']
        return None

    @property
    def cookie_domains(self):
        if 'cookieDomain' in self._results:
            return self._results['cookieDomain']
        return None

    @property
    def domains(self):
        if 'pageDomain' in self._results:
            return self._results['pageDomain']
        return None

    @property
    def start_date(self):
        if 'startDate' in self._results:
            return self._results['startDate']
        return None

    @property
    def guid(self):
        if 'guid' not in self._results:
            raise KeyError('No guid found for crawl index result')
        return str(self._results['guid'])

    @property
    def crawl_index_url(self):
        return self._crawl_url % self.guid


class CrawlIndex(object):
    _solr_url = 'http://crawlindex.vip.riskiq:8983/crawlIndex/select/?q=%s:%s&version=2.2&rows=%d&wt=json'
    _default_limit = 100

    def __init__(self, limit=None):
        if limit:
            self._default_limit = limit

    def _query(self, query_type, query, limit=None):
        if not limit:
            limit = self._default_limit
        url = self._solr_url % (query_type, query, limit)
        results = requests.get(url).json()
        if 'response' in results and results['response']['numFound'] > 0:
            results = [CrawlIndexResult(i, query_type) for i in results['response']['docs']]
        return results

    def query_by_domain(self, domain, limit=None):
        return self._query('pageDomain', domain, limit)

    def query_by_ip(self, ip, limit=None):
        return self._query('ip', ip, limit)