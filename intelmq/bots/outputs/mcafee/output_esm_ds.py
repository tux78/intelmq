# -*- coding: utf-8 -*-
"""
ESMOutputBot connects to McAfee Enterprise Security Manager, and boards a datasource

Parameters:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user

"""

from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError

import json

try:
    import requests
except ImportError:
    requests = None
try:
    import base64
except ImportError:
    base64 = None



class ESMDSOutputBot(Bot):

    def init(self):
        if requests is None:
            raise MissingDependencyError("requests")
        if base64 is None:
            raise MissingDependencyError("base64")

        self.esm = ESM(
            self.parameters.esm_ip,
            self.parameters.esm_user,
            self.parameters.esm_password
        )
        try:
            self.esm.login()
            self.esm.logout()
        except Exception:
            raise ValueError('Could not Login to ESM.')


    def process(self):
        event = self.receive_message()
        self.logger.info('Message received.')

        datasources = event.get ('output')
        if datasources is None:
            self.acknowledge_message()
            raise ValueError('No Data provided.')

        try:
            self.esm.login ()
            response = self.esm.dsAddDataSources (json.loads(datasources))
            self.logger.info('ESM data sources added.\r\n' + str(response))
            self.acknowledge_message()
        except Exception:
            self.logger.exception('Error when adding data sources.')

class ESM ():

    ESM_DEFAULT_FIELDS = [
        'name',
        'ipAddress',
        'typeId',
        'zoneId',
        'enabled',
        'url'
    ]


    def __init__ (self, esm_ip, esm_user, esm_pw):
        self.url = "https://{}/rs/esm/v2/".format(esm_ip)
        self.user = base64.b64encode(esm_user.encode('utf-8')).decode()
        self.pw = base64.b64encode(esm_pw.encode('utf-8')).decode()

        self.headers = {
            'content-type': 'application/json'
        }

    def login (self):

        payload = {
            'username': self.user,
            'password': self.pw,
            'locale': 'en_US',
            'os': 'Win32'
        }
        response = self._esm_sendquery ('login', payload)
        self.headers['X-Xsrf-Token'] = response.headers['Xsrf-Token']
        self.headers['Cookie'] = response.headers['Set-Cookie']

    def logout (self):
        response = self._esm_sendquery ('logout', '')
        del self.headers['X-Xsrf-Token']
        del self.headers['Cookie']

    def dsAddDataSources (self, datasource):

        payload = self._create_ds_json (datasource)
        response = self._esm_sendquery ('dsAddDataSources', payload)
        return payload

    def dsGetDataSourceTypes (self, receiverId):

        payload = {
            'receiverId': receiverId
        }
        response = self._esm_sendquery ('dsGetDataSourceTypes', payload)
        return response.json()

    def _create_ds_json (self, payload):

        retVal = {}
        retVal['receiverId'] = payload['receiverId']
        retVal['datasources'] = []

        datasource = {}
        datasource['parameters'] = []
        if 'typeId' not in datasource:
            datasourcetypes = self.dsGetDataSourceTypes (payload['receiverId'])
            for vendor in datasourcetypes['vendors']:
                if vendor['name'] == payload['vendor']:
                    for model in vendor['models']:
                        if model['name'] == payload['model']:
                            payload['typeId'] = model['id']
                            break

        for key in payload:
            if key in self.ESM_DEFAULT_FIELDS:
                datasource[key] = payload[key]
            elif payload[key] != '':
                parameter = {
                    'key': key,
                    'value': payload[key]
                }
                datasource['parameters'].append (parameter)

        retVal['datasources'].append (datasource)
        return retVal
                
    def _esm_sendquery (self, method, payload):

        if 'X-Xsrf-Token' not in self.headers and method != 'login':
            raise ValueError('You have to login first.')

        response = requests.post(
            self.url + method,
            headers = self.headers,
            data = json.dumps (payload),
            verify = False
        )

        return response

BOT = ESMDSOutputBot
