#!/usr/bin/env python
__author__ = 'RiskIQ Research'
__version__ = '0.1-ALPHA'
import json


class GenericOutput(object):
    def __init__(self, results):
        api_results = []
        if type(results) is list:
            for api_result in results:
                if 'records' in api_result:
                    r = api_result.pop('records')
                    api_results.extend(r)
        elif type(results) is dict:
            if 'records' in results:
                api_results = results['records']
        self._results = api_results

    @property
    def results(self):
        return self._results

    @property
    def csv(self):
        raise NotImplemented('CSV Output Not Implemented')

    @property
    def json(self):
        return json.dumps(self._results, indent=4, separators=(',', ': '))

    @property
    def count(self):
        return list(self._results)

    @property
    def text(self):
        return str(self._results)

    @property
    def count(self):
        return len(self._results)


class PassiveDNS(GenericOutput):
    @property
    def text(self):
        r = list()
        for record in self._results:
            rname = '-- %s ' % record['name'] + '-' * (60-len(record['name']))
            r.append(rname)
            r.append('Times Seen: %s' % record['count'])
            r.append('Record Type: %s' % record['rrtype'])
            r.append('Record First Seen: %s' % record['firstSeen'])
            r.append('Record Last Seen: %s' % record['lastSeen'])
            r.append('Record Responses: %s' % '\n                  '.join(record['data']))
        return '\n'.join(r)

    @property
    def csv(self):
        return
